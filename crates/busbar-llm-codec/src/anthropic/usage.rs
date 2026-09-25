// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic `usage` objects: the cache-tier read and the buffered / `message_delta` usage writers.

/// Read Anthropic's 5m/1h cache-creation TIER SPLIT off a wire `usage` object into the neutral
/// [`crate::ir::IrUsageDetail`].
///
/// The two tiers are SLICES of `cache_creation_input_tokens`, never additions to it, but they are
/// PRICED DIFFERENTLY — collapsing them into the one total leaves a bill that reconciles in aggregate
/// and cannot be reconciled per line. Factored out of `read_response` so the STREAMING sites
/// (`message_start` and `message_delta`) read the identical object instead of defaulting the split
/// away: the same request must not report the tier split at `stream: false` and lose it at
/// `stream: true`.
///
/// The PRICED counts here — both cache tiers and the separately-metered `web_search_requests` — are
/// read through [`crate::usage_count::billed_count_opt`] (#42, item 133): absent or `null` is
/// `None`, a present-but-UNREADABLE count is an [`crate::usage_count::UnreadableCount`] the caller
/// turns into a refusal. The old read returned `None` for it, which reads as "not reported".
/// `reasoning_tokens` stays a lenient read: it is ATTRIBUTION inside `output_tokens` (already
/// billed there), not a priced term, exactly as item 133 left the other dialects' reasoning slices.
pub(super) fn read_cache_tier_detail(
    usage_val: Option<&serde_json::Value>,
) -> Result<crate::ir::IrUsageDetail, crate::usage_count::UnreadableCount> {
    let tiers = usage_val.and_then(|u| u.get("cache_creation"));
    Ok(crate::ir::IrUsageDetail {
        cache_creation_5m_input_tokens: crate::usage_count::billed_count_opt(
            tiers,
            "ephemeral_5m_input_tokens",
        )?,
        cache_creation_1h_input_tokens: crate::usage_count::billed_count_opt(
            tiers,
            "ephemeral_1h_input_tokens",
        )?,
        // `usage.server_tool_use.web_search_requests` — count of server-side web-search invocations,
        // a separately-metered bucket (see the IR field). Read alongside the cache tiers so the
        // buffered AND streaming usage sites all surface it.
        web_search_requests: crate::usage_count::billed_count_opt(
            usage_val.and_then(|u| u.get("server_tool_use")),
            "web_search_requests",
        )?,
        // `usage.service_tier` — which tier served/billed the turn (`standard`/`priority`/`batch`).
        service_tier: usage_val
            .and_then(|u| u.get("service_tier"))
            .and_then(|v| v.as_str())
            .map(String::from),
        // `usage.output_tokens_details.thinking_tokens` — the reasoning slice of `output_tokens`.
        // The IR already has a neutral slot for it (OpenAI `reasoning_tokens`, Gemini
        // `thoughtsTokenCount`), so read it into that slot rather than dropping it.
        reasoning_tokens: usage_val
            .and_then(|u| u.get("output_tokens_details"))
            .and_then(|d| d.get("thinking_tokens"))
            .and_then(crate::usage_count::read_count_u64),
        ..Default::default()
    })
}

/// The `cache_creation` tier object for a wire `usage`, in Anthropic's native nested
/// `{ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}` spelling. The published `Usage` schema
/// requires the member and requires both counters inside it, so:
///
/// * a reported tier is emitted as-is, with the unreported sibling as `0` (the tiers are slices of
///   `cache_creation_input_tokens`, so a missing one really is zero);
/// * no tier reported and no cache write at all (`cache_creation_input_tokens` absent or 0) — the
///   all-zero object a real uncached Anthropic response carries;
/// * no tier reported but a non-zero cache write (a foreign backend that only knows the total,
///   e.g. Bedrock `cacheWriteInputTokens`) — `null`, the schema's nullable form, rather than an
///   invented split that would not sum to the total.
pub(super) fn write_cache_creation_object(usage: &crate::ir::IrUsage) -> serde_json::Value {
    let d = &usage.detail;
    let any_tier =
        d.cache_creation_5m_input_tokens.is_some() || d.cache_creation_1h_input_tokens.is_some();
    if !any_tier && usage.cache_creation_input_tokens.unwrap_or(0) > 0 {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "ephemeral_5m_input_tokens": d.cache_creation_5m_input_tokens.unwrap_or(0),
        "ephemeral_1h_input_tokens": d.cache_creation_1h_input_tokens.unwrap_or(0),
    })
}

/// `usage.output_tokens_details` — `{thinking_tokens: N}` when the reasoning slice is known,
/// else the schema's `null`. Required by both `Usage` and `MessageDeltaUsage`.
pub(super) fn write_output_tokens_details(usage: &crate::ir::IrUsage) -> serde_json::Value {
    match usage.detail.reasoning_tokens {
        Some(t) => serde_json::json!({ "thinking_tokens": t }),
        None => serde_json::Value::Null,
    }
}

/// `usage.server_tool_use` — Anthropic's `{web_search_requests, web_fetch_requests}` object when a
/// server-tool count is known, else the schema's `null` (what a real response carries when no
/// server tool ran). Required by both `Usage` and `MessageDeltaUsage`. The IR carries only the
/// web-search count; the schema requires both counters, so `web_fetch_requests` is `0` here.
pub(super) fn write_server_tool_use(usage: &crate::ir::IrUsage) -> serde_json::Value {
    match usage.detail.web_search_requests {
        Some(n) => serde_json::json!({ "web_search_requests": n, "web_fetch_requests": 0 }),
        None => serde_json::Value::Null,
    }
}

/// Build the full wire `usage` object of a `Message` (the buffered response and the
/// `message_start.message` skeleton, which the published spec types as the same `Usage` schema).
///
/// Every member the spec marks REQUIRED is always present, in the spec's own nullable/default shape
/// when busbar has no value: the two cache counters as `0` (a real uncached Anthropic response
/// reports zeros, never omits them), `cache_creation` as the zero tier object, `service_tier` as
/// `"standard"` (the tier a request lands on unless it asked for another), and `inference_geo`,
/// `output_tokens_details`, `server_tool_use` as `null`. A value the source reported is emitted
/// unchanged. `None` (a cross-protocol stream whose first frame carried no usage) yields the
/// zero-valued skeleton.
pub(super) fn write_usage_object(usage: Option<&crate::ir::IrUsage>) -> serde_json::Value {
    let zero = crate::ir::IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
        detail: crate::ir::IrUsageDetail::default(),
    };
    let usage = usage.unwrap_or(&zero);
    let mut usage_map = serde_json::Map::new();
    usage_map.insert(
        "input_tokens".to_string(),
        serde_json::json!(usage.input_tokens),
    );
    usage_map.insert(
        "output_tokens".to_string(),
        serde_json::json!(usage.output_tokens),
    );
    usage_map.insert(
        "cache_creation_input_tokens".to_string(),
        serde_json::json!(usage.cache_creation_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        "cache_read_input_tokens".to_string(),
        serde_json::json!(usage.cache_read_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        "cache_creation".to_string(),
        write_cache_creation_object(usage),
    );
    usage_map.insert("inference_geo".to_string(), serde_json::Value::Null);
    usage_map.insert(
        "output_tokens_details".to_string(),
        write_output_tokens_details(usage),
    );
    usage_map.insert("server_tool_use".to_string(), write_server_tool_use(usage));
    usage_map.insert(
        "service_tier".to_string(),
        serde_json::json!(
            anthropic_served_tier(usage.detail.service_tier.as_deref()).unwrap_or("standard")
        ),
    );
    serde_json::Value::Object(usage_map)
}

/// The IR served-tier attribution → an Anthropic `usage.service_tier` word, or `None` when
/// Anthropic has no word for it. The IR slot can carry OpenAI-family words (a Chat backend's
/// `flex` / `scale`, which the Chat reader keeps so the two OpenAI dialects agree); an Anthropic
/// client's SDK types the member as `standard | priority | batch`, so an unknown word is never
/// written — it is DROPPED with a warn and the member takes its absent form.
/// OpenAI's `default` IS the standard tier.
pub(super) fn anthropic_served_tier(tier: Option<&str>) -> Option<&'static str> {
    let word = tier?;
    let mapped = match word {
        "standard" | "default" => Some("standard"),
        "priority" => Some("priority"),
        "batch" => Some("batch"),
        _ => None,
    };
    if mapped.is_none() {
        tracing::warn!(
            service_tier = word,
            "dropping usage.service_tier on Anthropic response egress: Anthropic names only \
             standard / priority / batch"
        );
    }
    mapped
}

/// Build the wire `usage` object of a `message_delta` event (`MessageDeltaUsage`). The spec
/// requires `input_tokens`, `output_tokens`, both cache counters, `output_tokens_details` and
/// `server_tool_use`; they are always present, zero/null when busbar has no value. The 5m/1h tier
/// split and `service_tier` are not members of that schema, so they are still emitted only when the
/// source reported them — the same request must reconcile per tier at `stream: true` exactly as it
/// does at `stream: false`, and a stream must not lose an attribution the buffered path reports.
pub(super) fn write_message_delta_usage(usage: &crate::ir::IrUsage) -> serde_json::Value {
    let mut usage_map = serde_json::Map::new();
    usage_map.insert(
        "input_tokens".to_string(),
        serde_json::json!(usage.input_tokens),
    );
    usage_map.insert(
        "output_tokens".to_string(),
        serde_json::json!(usage.output_tokens),
    );
    usage_map.insert(
        "cache_creation_input_tokens".to_string(),
        serde_json::json!(usage.cache_creation_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        "cache_read_input_tokens".to_string(),
        serde_json::json!(usage.cache_read_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        "output_tokens_details".to_string(),
        write_output_tokens_details(usage),
    );
    usage_map.insert("server_tool_use".to_string(), write_server_tool_use(usage));
    let d = &usage.detail;
    if d.cache_creation_5m_input_tokens.is_some() || d.cache_creation_1h_input_tokens.is_some() {
        usage_map.insert(
            "cache_creation".to_string(),
            write_cache_creation_object(usage),
        );
    }
    if let Some(tier) = anthropic_served_tier(d.service_tier.as_deref()) {
        usage_map.insert("service_tier".to_string(), serde_json::json!(tier));
    }
    serde_json::Value::Object(usage_map)
}
