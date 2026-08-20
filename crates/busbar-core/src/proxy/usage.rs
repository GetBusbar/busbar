use super::*;

/// Charge a non-streaming response's token usage to the virtual key's budget, sourced from the
/// IR. The streaming path bills from `translate.usage()` inside `FirstByteBody`; buffered
/// (non-streaming) cross-protocol responses already decode the egress body egress→IR→ingress, so the
/// terminal `IrUsage` is available WITHOUT a separate byte-scan — bill straight from `ir.usage`.
///
/// Billed tokens = the normalized billable total: `uncached_input + cache_read +
/// cache_creation + output` (see [`crate::ir::IrUsage::billable_tokens`]). Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so this sum is correct
/// provider-agnostically. This matches the streaming billing arm.
/// OPERATION-BLIND usage recording: project the response IR's neutral `Billing` and record token
/// meters through the existing sink (identical numbers for chat — the Billing round-trip preserves
/// the additive-cache convention). Non-token meters (duration/characters/images/flat) are carried in
/// the client-visible body today and priced by the 1.3 engine; nothing to record here yet.
pub(crate) fn record_resp_usage(
    ir: &crate::ir::variant::IrResp,
    usage_sink: &Option<UsageSink>,
    lane: Option<&crate::state::Lane>,
) {
    if let Some(crate::billing::Billing::Tokens(t)) = ir.usage() {
        // `ir.usage()` is ALREADY the neutral `Billing::Tokens(TokenUsage)` projection — bill straight
        // from it. The prior code re-packed it into a concrete `IrUsage` only to have the consumer read
        // the same four totals back out; that round-trip is deleted (byte-identical: the ledger/meter
        // sinks read only input/output/cache-read/cache-write).
        record_token_usage(&t, usage_sink, lane);
    } else if let Some(sink) = usage_sink {
        // A delivered response with NO token usage (a flat-fee op, e.g. moderations) still METERS as
        // one request against the serving model — FinOps consumers count requests per model even
        // when nothing token-bills.
        if let Some(lane) = lane {
            sink.gov.record_metering(
                &sink.key.id,
                &lane.model,
                &lane.provider,
                None,
                sink.charged_at,
            );
        }
    }
}

/// Recover token usage from a TAIL-anchored same-protocol non-stream billing buffer
/// (`response_body.rs`'s `nonstream_buf`) whose HEAD was dropped to keep it bounded at
/// `max_translated_body_bytes()`. The retained slice is no longer a well-formed top-level JSON
/// document (its opening structure — or a string it cut through — is gone), so the normal
/// `Op::extract_usage` full-document parse reliably fails on it. But the `usage` object itself sits
/// at (or near) the TAIL of every supported dialect's response and is a small, SELF-CONTAINED
/// balanced `{...}` value, so it can be isolated and parsed on its own even though the surrounding
/// document cannot be.
///
/// Scoped to the dialects with a documented, stable usage shape (openai/anthropic/gemini/
/// openai_responses/cohere/bedrock share the field names below); an unrecognized protocol or a
/// usage object that itself doesn't fit in the retained tail (never observed — a usage object is a
/// handful of integer fields) returns `None`, which the caller already treats as "bill zero,
/// counted+warned" — no worse than before this fix, just narrower than the common case it now
/// recovers.
pub(crate) fn recover_truncated_usage(
    ingress_protocol: &str,
    tail: &[u8],
) -> Option<crate::ir::IrUsage> {
    let key: &[u8] = if ingress_protocol == "gemini" {
        b"\"usageMetadata\""
    } else {
        b"\"usage\""
    };
    let key_pos = find_last(tail, key)?;
    let obj = balanced_object_after(tail, key_pos + key.len())?;
    let v: serde_json::Value = crate::json::parse(obj).ok()?;
    Some(usage_from_tapped_value(ingress_protocol, &v))
}

/// Find the LAST occurrence of `needle` in `hay` (there can be more than one `"usage"` substring —
/// e.g. inside delivered assistant content — so anchoring on the last one biases toward the real
/// trailing usage object, which is where every dialect places it).
fn find_last(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// From just past a `"usage"`/`"usageMetadata"` key, skip the `:` and whitespace, then
/// bracket-match the following `{...}` object (string- and escape-aware, so a `}` inside a quoted
/// string value does not close the object early). Returns the byte span INCLUDING both braces.
fn balanced_object_after(buf: &[u8], mut i: usize) -> Option<&[u8]> {
    while i < buf.len() && (buf[i] as char).is_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < buf.len() && (buf[i] as char).is_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b'{') {
        return None;
    }
    let start = i;
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escape = false;
    while i < buf.len() {
        let c = buf[i];
        if in_str {
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&buf[start..=i]);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Decode an isolated usage object into `IrUsage`, mirroring each protocol reader's own
/// `read_response` usage block (openai_chat.rs / anthropic/reader.rs / gemini/mod.rs's
/// `gemini_usage` / openai_responses/reader.rs / cohere/reader.rs / bedrock/reader.rs) — duplicated
/// here rather than reused because those readers operate on the WHOLE response body (they require
/// `choices`/`candidates`/`content` to be present), which a tail-truncated buffer by definition does
/// not have. Only the small set of fields billing actually needs is mirrored.
fn usage_from_tapped_value(ingress_protocol: &str, v: &serde_json::Value) -> crate::ir::IrUsage {
    let zero = || crate::ir::IrUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
        detail: crate::ir::IrUsageDetail::default(),
    };
    let u64_field = |k: &str| v.get(k).and_then(|x| x.as_u64());
    match ingress_protocol {
        "anthropic" => crate::ir::IrUsage {
            input_tokens: u64_field("input_tokens").unwrap_or(0),
            output_tokens: u64_field("output_tokens").unwrap_or(0),
            cache_creation_input_tokens: u64_field("cache_creation_input_tokens"),
            cache_read_input_tokens: u64_field("cache_read_input_tokens"),
            ..zero()
        },
        "gemini" => {
            let cached = v.get("cachedContentTokenCount").and_then(|x| x.as_u64());
            crate::ir::IrUsage {
                input_tokens: v
                    .get("promptTokenCount")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0)
                    .saturating_sub(cached.unwrap_or(0)),
                output_tokens: v
                    .get("candidatesTokenCount")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                cache_read_input_tokens: cached,
                ..zero()
            }
        }
        "bedrock" => crate::ir::IrUsage {
            input_tokens: u64_field("inputTokens").unwrap_or(0),
            output_tokens: u64_field("outputTokens").unwrap_or(0),
            cache_creation_input_tokens: u64_field("cacheWriteInputTokens"),
            cache_read_input_tokens: u64_field("cacheReadInputTokens"),
            ..zero()
        },
        "cohere" => {
            let tokens = v.get("tokens");
            crate::ir::IrUsage {
                input_tokens: tokens
                    .and_then(|t| t.get("input_tokens"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                output_tokens: tokens
                    .and_then(|t| t.get("output_tokens"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                ..zero()
            }
        }
        // openai_responses: input_tokens/output_tokens; openai (chat completions):
        // prompt_tokens/completion_tokens. Both are grouped under the "openai"/"openai_responses"
        // ingress names, so disambiguate on which field the object actually carries.
        _ => {
            if v.get("prompt_tokens").is_some() || v.get("completion_tokens").is_some() {
                let cached = v
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|x| x.as_u64());
                crate::ir::IrUsage {
                    input_tokens: u64_field("prompt_tokens")
                        .unwrap_or(0)
                        .saturating_sub(cached.unwrap_or(0)),
                    output_tokens: u64_field("completion_tokens").unwrap_or(0),
                    cache_read_input_tokens: cached,
                    ..zero()
                }
            } else {
                let cached = v
                    .get("input_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|x| x.as_u64());
                crate::ir::IrUsage {
                    input_tokens: u64_field("input_tokens")
                        .unwrap_or(0)
                        .saturating_sub(cached.unwrap_or(0)),
                    output_tokens: u64_field("output_tokens").unwrap_or(0),
                    cache_read_input_tokens: cached,
                    ..zero()
                }
            }
        }
    }
}

/// Project the IR's normalized usage into the LEDGER'S four pricing tiers. Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so the mapping is direct:
/// cache-creation is the rate card's `cache_write` tier.
pub(crate) fn tier_tokens(u: &crate::billing::TokenUsage) -> busbar_api::TierTokens {
    busbar_api::TierTokens {
        input: u.input,
        output: u.output,
        cache_read: u.cache_read.unwrap_or(0),
        cache_write: u.cache_creation.unwrap_or(0),
    }
}

/// THE ONE PLACE a delivered response is attributed to a model — for the budget LEDGER and for the
/// METERING series both. Every accrual site in the proxy funnels through here so the two can never
/// again be keyed differently.
///
/// THE MODEL KEY IS THE CONFIG NAME (`lane.model`), NOT THE WIRE NAME (`lane.wire_model()`).
/// The rate card is keyed by the CONFIG model name, and `validate_cost_model` enforces that in both
/// directions: every `models:` key must have a card entry, and a card entry naming anything that is
/// not a `models:` key is a boot error. All three accrual sites nonetheless passed
/// `lane.wire_model()`, which returns `upstream_model` whenever a lane sets one — so for every
/// aliased lane (the documented flagship multi-provider setup) `CostModel::rate_for` looked up a
/// string that CANNOT be in the card, silently took the `None` arm, and derived spend of ZERO.
/// Consequences: a group with a `budget:` limit counted only the flat per-request fee for that
/// traffic — effectively uncapped on token cost — `busbar_bucket_spend_cents` reported 0 with full
/// headroom, and the two spend surfaces disagreed, because metering (three lines below) was already
/// keyed by `lane.model` and priced correctly on `/api/v1/admin/usage`.
///
/// `wire_model()` remains right for what it is named after: the string sent to the provider. It is
/// simply not an accounting key, and there is now one function rather than three that has to know
/// the difference.
///
/// `lane` is the SERVING lane (post-failover). `None` — an unknown/unresolvable lane — can attribute
/// tokens to no model, so nothing is ledgered or metered (unreachable in production: every delivered
/// response has a serving lane).
pub(crate) fn ledger_and_meter(
    sink: &UsageSink,
    lane: &crate::state::Lane,
    usage: Option<&crate::billing::TokenUsage>,
    tier: &busbar_api::TierTokens,
) {
    // Ledger the TIER SPLIT (uncached input / output / cache-read / cache-write — each prices
    // differently under the rate card) against the key's budget chain, in the SAME window as the
    // flat per-request fee (`sink.charged_at`, the header-arrival epoch), so token accrual and the
    // per-request fee never split across windows (#29). `record_usage` no-ops on an all-zero tier.
    sink.gov.record_usage(
        &sink.cost,
        &sink.key,
        &sink.pool,
        &lane.model,
        tier,
        sink.charged_at,
    );
    // Metering (raw per-model consumption series, token SPLIT preserved) — even a zero-token
    // delivered response counts its request. Same pinned epoch as the budget charges (#29).
    sink.gov.record_metering(
        &sink.key.id,
        &lane.model,
        &lane.provider,
        usage,
        sink.charged_at,
    );
}

/// `lane` is the SERVING lane - the model attribution for BOTH the token ledger and the metering
/// series (see [`ledger_and_meter`], which owns the choice of key).
/// `None` (an unknown/unresolvable lane) can attribute tokens to no model, so nothing is ledgered
/// or metered (unreachable in production: every delivered response has a serving lane).
pub(crate) fn record_token_usage(
    usage: &crate::billing::TokenUsage,
    usage_sink: &Option<UsageSink>,
    lane: Option<&crate::state::Lane>,
) {
    if let Some(sink) = usage_sink {
        let Some(lane) = lane else { return };
        ledger_and_meter(sink, lane, Some(usage), &tier_tokens(usage));
    }
}

/// The bounded `pool` LABEL for an UPSTREAM/breaker metric.
///
/// The breaker-CELL key (`pool_name`) is `""` for the lane-default cell shared by every
/// direct/ad-hoc (single-model) route — that empty string is the correct CELL key and must NOT be
/// repointed (the cell identity drives breaker state, /stats, /healthz). But emitting it verbatim
/// as the `pool` metric LABEL mislabels all model-routed upstream traffic under an empty-string
/// series, whereas `REQUESTS_TOTAL` (via `ingress::pool_label`) labels the SAME request stream with
/// the MODEL name. That split makes upstream metrics impossible to correlate with the request
/// counter for non-pool traffic. Resolve the metric label to the routed lane's model name when the
/// cell key is empty, leaving named-pool traffic labeled by its pool name. This decouples the metric
/// label from the cell key WITHOUT touching the cell key itself.
pub(crate) fn metric_pool_label<'a>(app: &'a Arc<App>, pool_name: &'a str, i: usize) -> &'a str {
    if pool_name.is_empty() {
        app.lanes[i].model.as_str()
    } else {
        pool_name
    }
}

/// Emit `BREAKER_TRIPS_TOTAL` once for a logical Closed→Open trip on a (pool, lane) cell. Called from
/// the organic forward path's failure-record sites whenever `record_transient_in`/`record_rate_limit_in`
/// reports a fresh trip, mirroring the HardDown arm so threshold-based trips are counted too (#29). The
/// `pool` label is the bounded, operator-controlled canonical pool name, or the routed model name for
/// the default (`""`) cell (see `metric_pool_label`) so it correlates with REQUESTS_TOTAL.
pub(crate) fn emit_breaker_trip(app: &Arc<App>, pool_name: &str, i: usize) {
    crate::telemetry::breaker_trip(app, metric_pool_label(app, pool_name, i), i);
    tracing::warn!(pool = %pool_name, lane = %app.lanes[i].model, "lane breaker tripped (Closed→Open)");
}

/// The effective per-attempt time-to-response-headers cap for pool member `i`: the pool-member
/// override wins over the model-level default (`None` = uncapped). This is the layering the
/// feature promises — the SAME model can be `attempt_timeout_ms: 10000` in a batch pool and
/// `50` in a latency-critical pool, with the model-level value as the fallback for pools (and
/// the default `""` cell) that don't override it.
pub(crate) fn effective_attempt_timeout_ms(
    cands: &[crate::state::WeightedLane],
    i: usize,
    lane_default: Option<u64>,
) -> Option<u64> {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.attempt_timeout_ms)
        .or(lane_default)
}

/// The effective per-lane reasoning capability for pool member `i`: the pool-member override wins
/// over the model-level flag (same layering as `effective_attempt_timeout_ms`), default false —
/// a lane never receives thinking params unless some level of config claimed the capability.
pub(crate) fn effective_reasoning(
    cands: &[crate::state::WeightedLane],
    i: usize,
    lane_default: bool,
) -> bool {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.reasoning)
        .unwrap_or(lane_default)
}

/// Floor an `attempt_timeout_ms` cap by the request's remaining wall-clock budget (whole seconds),
/// so a per-attempt cap can never grant MORE time than the request has left — mirroring how the
/// reqwest transport timeout is budget-clamped. `.max(1)` keeps the cap non-zero on a nearly
/// exhausted budget (a zero-duration timeout would fail the attempt before it is even tried).
pub(crate) fn attempt_cap(ms: u64, remaining_secs: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms.min(remaining_secs.saturating_mul(1000).max(1)))
}
