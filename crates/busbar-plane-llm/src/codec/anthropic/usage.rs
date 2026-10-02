// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic `usage` objects: the usage table and the buffered / `message_delta` usage writers.

use super::IrError;
use crate::codec::keys;
use crate::codec::usage_count::{read_usage, CountRead, CountSlot, UsageCount};

/// ANTHROPIC'S USAGE COUNTS, AS DATA (#42). The four totals come first: a truncated-body recovery
/// reads only those (`USAGE[..4]`). Then the 5m/1h cache-creation TIER SPLIT — SLICES of
/// `cache_creation_input_tokens`, never additions to it, but two separate tiers — the
/// separately-metered `server_tool_use.web_search_requests`, and the thinking slice of
/// `output_tokens` (attribution: already counted inside the output total, so a lenient read).
/// The buffered response and both stream frames (`message_start`, `message_delta`) read the same
/// table, so one request never reports the split at `stream: false` and loses it at `stream: true`.
pub(super) const USAGE: &[UsageCount] = &[
    (CountSlot::Input, CountRead::Zero(&[keys::INPUT_TOKENS])),
    (CountSlot::Output, CountRead::Zero(&[keys::OUTPUT_TOKENS])),
    (
        CountSlot::CacheWrite,
        CountRead::Opt(&[super::CACHE_CREATION_INPUT_TOKENS]),
    ),
    (
        CountSlot::CacheRead,
        CountRead::Opt(&[super::CACHE_READ_INPUT_TOKENS]),
    ),
    (
        CountSlot::CacheWrite5m,
        CountRead::Opt(&[super::CACHE_CREATION, super::EPHEMERAL_5M_INPUT_TOKENS]),
    ),
    (
        CountSlot::CacheWrite1h,
        CountRead::Opt(&[super::CACHE_CREATION, super::EPHEMERAL_1H_INPUT_TOKENS]),
    ),
    (
        CountSlot::WebSearchRequests,
        CountRead::Opt(&[super::SERVER_TOOL_USE, super::WEB_SEARCH_REQUESTS]),
    ),
    (
        CountSlot::Reasoning,
        CountRead::Lenient(&[keys::OUTPUT_TOKENS_DETAILS, super::THINKING_TOKENS]),
    ),
];

/// This dialect's label on a refused usage count.
pub(super) const COUNT_LABEL: &str = super::VENDOR_NAME;

/// An Anthropic wire `usage` object (`None` when the frame carries none) → the IR usage: the
/// [`USAGE`] table, plus `usage.service_tier` — which tier served the turn
/// (`standard`/`priority`/`batch`), a word rather than a count.
pub(super) fn read_anthropic_usage(
    usage_val: Option<&serde_json::Value>,
) -> Result<crate::codec::ir::IrUsage, IrError> {
    let mut usage = read_usage(COUNT_LABEL, usage_val, USAGE)?;
    usage.detail.service_tier = usage_val
        .and_then(|u| u.get(keys::SERVICE_TIER))
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(usage)
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
pub(super) fn write_cache_creation_object(usage: &crate::codec::ir::IrUsage) -> serde_json::Value {
    let d = &usage.detail;
    let any_tier =
        d.cache_creation_5m_input_tokens.is_some() || d.cache_creation_1h_input_tokens.is_some();
    if !any_tier && usage.cache_creation_input_tokens.unwrap_or(0) > 0 {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        (super::EPHEMERAL_5M_INPUT_TOKENS): d.cache_creation_5m_input_tokens.unwrap_or(0),
        (super::EPHEMERAL_1H_INPUT_TOKENS): d.cache_creation_1h_input_tokens.unwrap_or(0),
    })
}

/// `usage.output_tokens_details` — `{thinking_tokens: N}` when the reasoning slice is known,
/// else the schema's `null`. Required by both `Usage` and `MessageDeltaUsage`.
pub(super) fn write_output_tokens_details(usage: &crate::codec::ir::IrUsage) -> serde_json::Value {
    match usage.detail.reasoning_tokens {
        Some(t) => serde_json::json!({ (super::THINKING_TOKENS): t }),
        None => serde_json::Value::Null,
    }
}

/// `usage.server_tool_use` — Anthropic's `{web_search_requests, web_fetch_requests}` object when a
/// server-tool count is known, else the schema's `null` (what a real response carries when no
/// server tool ran). Required by both `Usage` and `MessageDeltaUsage`. The IR carries only the
/// web-search count; the schema requires both counters, so `web_fetch_requests` is `0` here.
pub(super) fn write_server_tool_use(usage: &crate::codec::ir::IrUsage) -> serde_json::Value {
    match usage.detail.web_search_requests {
        Some(n) => serde_json::json!({ (super::WEB_SEARCH_REQUESTS): n, "web_fetch_requests": 0 }),
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
pub(super) fn write_usage_object(usage: Option<&crate::codec::ir::IrUsage>) -> serde_json::Value {
    let zero = crate::codec::ir::IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
        detail: crate::codec::ir::IrUsageDetail::default(),
    };
    let usage = usage.unwrap_or(&zero);
    let mut usage_map = serde_json::Map::new();
    usage_map.insert(
        keys::INPUT_TOKENS.to_string(),
        serde_json::json!(usage.input_tokens),
    );
    usage_map.insert(
        keys::OUTPUT_TOKENS.to_string(),
        serde_json::json!(usage.output_tokens),
    );
    usage_map.insert(
        super::CACHE_CREATION_INPUT_TOKENS.to_string(),
        serde_json::json!(usage.cache_creation_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        super::CACHE_READ_INPUT_TOKENS.to_string(),
        serde_json::json!(usage.cache_read_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        super::CACHE_CREATION.to_string(),
        write_cache_creation_object(usage),
    );
    usage_map.insert("inference_geo".to_string(), serde_json::Value::Null);
    usage_map.insert(
        keys::OUTPUT_TOKENS_DETAILS.to_string(),
        write_output_tokens_details(usage),
    );
    usage_map.insert(
        super::SERVER_TOOL_USE.to_string(),
        write_server_tool_use(usage),
    );
    usage_map.insert(
        keys::SERVICE_TIER.to_string(),
        serde_json::json!(
            anthropic_served_tier(usage.detail.service_tier.as_deref()).unwrap_or(super::STANDARD)
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
        super::STANDARD | "default" => Some(super::STANDARD),
        super::PRIORITY => Some(super::PRIORITY),
        super::BATCH => Some(super::BATCH),
        _ => None,
    };
    if mapped.is_none() {
        crate::codec::drops::writer_drop!(
            crate::codec::drops::member("service_tier"),
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            [service_tier = word,],
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
pub(super) fn write_message_delta_usage(usage: &crate::codec::ir::IrUsage) -> serde_json::Value {
    let mut usage_map = serde_json::Map::new();
    usage_map.insert(
        keys::INPUT_TOKENS.to_string(),
        serde_json::json!(usage.input_tokens),
    );
    usage_map.insert(
        keys::OUTPUT_TOKENS.to_string(),
        serde_json::json!(usage.output_tokens),
    );
    usage_map.insert(
        super::CACHE_CREATION_INPUT_TOKENS.to_string(),
        serde_json::json!(usage.cache_creation_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        super::CACHE_READ_INPUT_TOKENS.to_string(),
        serde_json::json!(usage.cache_read_input_tokens.unwrap_or(0)),
    );
    usage_map.insert(
        keys::OUTPUT_TOKENS_DETAILS.to_string(),
        write_output_tokens_details(usage),
    );
    usage_map.insert(
        super::SERVER_TOOL_USE.to_string(),
        write_server_tool_use(usage),
    );
    let d = &usage.detail;
    if d.cache_creation_5m_input_tokens.is_some() || d.cache_creation_1h_input_tokens.is_some() {
        usage_map.insert(
            super::CACHE_CREATION.to_string(),
            write_cache_creation_object(usage),
        );
    }
    if let Some(tier) = anthropic_served_tier(d.service_tier.as_deref()) {
        usage_map.insert(keys::SERVICE_TIER.to_string(), serde_json::json!(tier));
    }
    serde_json::Value::Object(usage_map)
}
