//! DF-MAP audit (ARCHITECT rulings 2026-10-02 items 1, 2, 4; and the served tier, a real miss with
//! an existing IR home): what the Gemini reader and writer now map.
use super::super::proto_codec::protocol_for;
use crate::codec::ir::IrBlock;
use serde_json::json;

fn read(body: &serde_json::Value) -> crate::codec::ir::IrResponse {
    protocol_for("gemini")
        .unwrap()
        .reader()
        .read_response(body)
        .expect("reads")
}

fn answer() -> serde_json::Value {
    json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]},
                           "finishReason": "STOP", "index": 0}],
           "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 4,
                             "totalTokenCount": 14}})
}

#[test]
fn grounding_chunks_read_as_a_web_search_record_and_write_back() {
    let mut body = answer();
    body["candidates"][0]["groundingMetadata"] = json!({"groundingChunks": [
        {"web": {"uri": "https://a.example/x", "title": "A"}}]});
    let resp = read(&body);
    assert!(
        matches!(&resp.content[0], IrBlock::HostedToolRecord { results, .. }
            if results.len() == 1 && results[0].url == "https://a.example/x"),
        "{:?}",
        resp.content
    );
    let out = protocol_for("gemini")
        .unwrap()
        .writer()
        .write_response(&resp);
    assert_eq!(
        out["candidates"][0]["groundingMetadata"]["groundingChunks"][0]["web"]["uri"],
        "https://a.example/x",
        "{out}"
    );
}

#[test]
fn safety_ratings_read_as_verdicts_without_their_probability() {
    let mut body = answer();
    body["candidates"][0]["safetyRatings"] = json!([
        {"category": "HARM_CATEGORY_HARASSMENT", "probability": "HIGH", "blocked": true},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"}]);
    let resp = read(&body);
    assert_eq!(resp.safety.len(), 2);
    assert!(resp.safety[0].blocked && resp.safety[0].flagged);
    assert!(!resp.safety[1].flagged);
    let out = protocol_for("gemini")
        .unwrap()
        .writer()
        .write_response(&resp);
    let ratings = &out["candidates"][0]["safetyRatings"];
    assert_eq!(ratings[0]["category"], "HARM_CATEGORY_HARASSMENT");
    assert!(ratings[0].get("probability").is_none(), "{out}");
}

#[test]
fn modality_details_cross_both_ways() {
    let mut body = answer();
    body["usageMetadata"]["promptTokensDetails"] = json!([
        {"modality": "TEXT", "tokenCount": 7}, {"modality": "IMAGE", "tokenCount": 3}]);
    let resp = read(&body);
    let m = resp.usage.detail.by_modality.clone().expect("by_modality");
    assert_eq!((m.input.text, m.input.image), (Some(7), Some(3)));
    let out = protocol_for("gemini")
        .unwrap()
        .writer()
        .write_response(&resp);
    assert_eq!(
        out["usageMetadata"]["promptTokensDetails"][1]["tokenCount"], 3,
        "{out}"
    );
}

#[test]
fn the_serving_tier_is_read() {
    let mut body = answer();
    body["usageMetadata"]["serviceTier"] = json!("flex");
    assert_eq!(
        read(&body).usage.detail.service_tier.as_deref(),
        Some("flex")
    );
}
