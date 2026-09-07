// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO CACHE-WRITE TTLs ARE PRICED DIFFERENTLY, SO THE SPLIT IS CARRIED.
//!
//! The pinned Bedrock service model (botocore @ e5c81226) gives `TokenUsage` a `cacheDetails`
//! member —
//!
//!   cacheDetails: CacheDetailsList   "Detailed breakdown of cache writes by TTL. Empty if no
//!                                     cache creation occurred. Sorted by TTL duration
//!                                     (1h before 5m)."
//!   CacheDetail:  { ttl: CacheTTL (enum "5m" | "1h"),
//!                   inputTokens: "Number of tokens written to cache with this TTL
//!                                 (cache creation tokens)" }
//!
//! — the same 5m/1h split Anthropic reports as `cache_creation.ephemeral_5m_input_tokens` /
//! `ephemeral_1h_input_tokens`, and the IR has carried it in exactly those two fields since that
//! reader landed, for exactly this reason: the two TTLs price differently, so collapsing them into
//! the one `cacheWriteInputTokens` total leaves a bill that reconciles in aggregate and cannot be
//! reconciled per line.
//!
//! The Bedrock reader read only the total. The split was dropped on every buffered response, every
//! streamed `metadata` frame, and every truncated-tail recovery — and the writer emitted none back,
//! so an Anthropic response crossing to a Bedrock client lost the split too.

use super::*;

fn usage_with_details() -> serde_json::Value {
    serde_json::json!({
        "inputTokens": 1000,
        "outputTokens": 200,
        "cacheWriteInputTokens": 500,
        "cacheReadInputTokens": 40,
        // The spec's own ordering: 1h before 5m.
        "cacheDetails": [
            { "ttl": "1h", "inputTokens": 300 },
            { "ttl": "5m", "inputTokens": 200 }
        ],
        "totalTokens": 1740
    })
}

/// The buffered response.
#[test]
fn a_buffered_response_carries_the_per_ttl_split() {
    let ir = BedrockReader
        .read_response(&serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": usage_with_details()
        }))
        .expect("reads");
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(500));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, Some(300));
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(200));
}

/// The streamed `metadata` frame, which carries the identical `usage` object.
#[test]
fn a_streamed_metadata_frame_carries_the_per_ttl_split() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = BedrockReader.read_response_events(
        "metadata",
        &serde_json::json!({ "type": "metadata", "usage": usage_with_details() }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the metadata frame carries usage");
    assert_eq!(usage.cache_creation_input_tokens, Some(500));
    assert_eq!(usage.detail.cache_creation_1h_input_tokens, Some(300));
    assert_eq!(usage.detail.cache_creation_5m_input_tokens, Some(200));
}

/// And back out on the write leg, in the shape and ORDER the spec declares (1h before 5m).
#[test]
fn the_write_leg_re_emits_the_split_in_the_declared_order() {
    let ir = BedrockReader
        .read_response(&serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": usage_with_details()
        }))
        .expect("reads");
    let writer = BedrockWriter;
    let out = writer.write_response(&ir);
    let details = out["usage"]["cacheDetails"]
        .as_array()
        .expect("cacheDetails must survive the hop");
    assert_eq!(details.len(), 2);
    assert_eq!(details[0]["ttl"], serde_json::json!("1h"));
    assert_eq!(details[0]["inputTokens"], serde_json::json!(300));
    assert_eq!(details[1]["ttl"], serde_json::json!("5m"));
    assert_eq!(details[1]["inputTokens"], serde_json::json!(200));
    assert_eq!(
        out["usage"]["cacheWriteInputTokens"],
        serde_json::json!(500)
    );
}

/// Only the TTLs the source actually reported appear: a turn that wrote one tier does not acquire
/// an invented zero entry for the other.
#[test]
fn only_the_reported_tiers_appear() {
    let ir = BedrockReader
        .read_response(&serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10, "outputTokens": 5, "totalTokens": 15,
                "cacheWriteInputTokens": 200,
                "cacheDetails": [{ "ttl": "5m", "inputTokens": 200 }]
            }
        }))
        .expect("reads");
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(200));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, None);
    let writer = BedrockWriter;
    let out = writer.write_response(&ir);
    let details = out["usage"]["cacheDetails"].as_array().expect("present");
    assert_eq!(details.len(), 1, "no invented tier: {out}");
    assert_eq!(details[0]["ttl"], serde_json::json!("5m"));
}

/// A response with no cache creation is byte-for-byte what it was: the spec says `cacheDetails` is
/// "Empty if no cache creation occurred", and busbar emits no member rather than an empty array it
/// never received.
#[test]
fn a_response_with_no_cache_creation_is_unchanged() {
    let ir = BedrockReader
        .read_response(&serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
        }))
        .expect("reads");
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, None);
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, None);
    let writer = BedrockWriter;
    let out = writer.write_response(&ir);
    assert!(
        out["usage"].get("cacheDetails").is_none(),
        "no cache creation was reported, so no member is invented: {out}"
    );
}
