//! DF-MAP audit: the Bedrock answer slots (ARCHITECT ruling 2026-10-02 item 1) and the served tier
//! (a real miss: the IR home existed, the reader did not fill it).
use super::super::proto_codec::protocol_for;
use serde_json::json;

fn answer() -> serde_json::Value {
    json!({"output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
           "stopReason": "end_turn",
           "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
           "metrics": {"latencyMs": 1}})
}

fn read(body: &serde_json::Value) -> crate::codec::ir::IrResponse {
    protocol_for("bedrock")
        .unwrap()
        .reader()
        .read_response(body)
        .expect("reads")
}

#[test]
fn the_serving_tier_is_read() {
    let mut body = answer();
    body["serviceTier"] = json!({"type": "flex"});
    assert_eq!(
        read(&body).usage.detail.service_tier.as_deref(),
        Some("flex")
    );
}

#[test]
fn guardrail_content_filters_read_as_safety_verdicts() {
    let mut body = answer();
    body["trace"] = json!({"guardrail": {
        "inputAssessment": {"g1": {"contentPolicy": {"filters": [
            {"type": "VIOLENCE", "confidence": "HIGH", "action": "BLOCKED", "detected": true},
            {"type": "HATE", "confidence": "NONE", "action": "NONE", "detected": false}]}}}}});
    let safety = read(&body).safety;
    assert_eq!(safety.len(), 1, "{safety:?}");
    assert_eq!(safety[0].category, "VIOLENCE");
    assert!(safety[0].blocked && safety[0].flagged);
}
