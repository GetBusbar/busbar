use super::*;

use busbar_substrate::diag_warn;
use busbar_substrate::diagnostics::LANE_BREAKER_TRIPPED;

/// Charge a non-streaming response's token usage to the virtual key's budget, sourced from the
/// IR. The streaming path bills from `translate.usage()` inside `FirstByteBody`; buffered
/// (non-streaming) cross-protocol responses already decode the egress body egress→IR→ingress, so the
/// terminal `IrUsage` is available WITHOUT a separate byte-scan — bill straight from `ir.usage`.
///
/// Billed tokens = the normalized billable total: `uncached_input + cache_read +
/// cache_creation + output` (see [`busbar_substrate::ir::IrUsage::billable_tokens`]). Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so this sum is correct
/// provider-agnostically. This matches the streaming billing arm.
/// OPERATION-BLIND usage recording: project the response IR's neutral `Billing` and record token
/// meters through the existing sink (identical numbers for chat — the Billing round-trip preserves
/// the additive-cache convention). Non-token meters (duration/characters/images/flat) are carried in
/// the client-visible body today and priced by the 1.3 engine; nothing to record here yet.
pub(crate) fn record_resp_usage(
    host: &Arc<dyn EngineHost>,
    usage: Option<busbar_substrate::billing::Billing>,
    usage_sink: &Option<UsageSink>,
    lane: Option<&crate::engine::Lane>,
) {
    if let Some(busbar_substrate::billing::Billing::Tokens(t)) = usage {
        // `usage` is ALREADY the neutral `Billing::Tokens(TokenUsage)` projection the response codec
        // captured from the read IR (before `prepare_for_ingress`) and handed back through
        // `TranslateCodec::translate_response` — bill straight from it. This seam never holds the
        // concrete IR (byte-identical: the ledger/meter sinks read only
        // input/output/cache-read/cache-write).
        record_token_usage(host, &t, usage_sink, lane);
    } else if let Some(sink) = usage_sink {
        // A delivered response with NO token usage (a flat-fee op, e.g. moderations) still METERS as
        // one request against the serving model — FinOps consumers count requests per model even
        // when nothing token-bills. Routed through the host `meter_series` seam over the sink's opaque
        // `GovHandle` — byte-identical to the pre-flip `sink.gov.record_metering(...)`.
        if let Some(lane) = lane {
            host.meter_series(
                &sink.gov,
                &sink.key.id,
                &lane.model,
                &lane.provider,
                None,
                sink.charged_at,
            );
        }
    }
}

/// Project the IR's normalized usage into the neutral name-keyed [`busbar_substrate::billing::Usage`]
/// carrier: the four reserved units (`input`/`output`/`cache_read`/`cache_write`) as canonical map
/// keys (M1b — `TierTokens` is dissolved). Readers normalize `input_tokens` to UNCACHED and keep the
/// cache fields ADDITIVE, so the mapping is direct: cache-creation is the `cache_write` unit. Zero
/// tiers are omitted so the map stays sparse (no-zero-entry).
pub(crate) fn tier_usage(
    u: &busbar_substrate::billing::TokenUsage,
) -> busbar_substrate::billing::Usage {
    let mut usage_units = std::collections::BTreeMap::new();
    for (k, v) in [
        (busbar_api::UNIT_INPUT, u.input),
        (busbar_api::UNIT_OUTPUT, u.output),
        (busbar_api::UNIT_CACHE_READ, u.cache_read.unwrap_or(0)),
        (busbar_api::UNIT_CACHE_WRITE, u.cache_creation.unwrap_or(0)),
    ] {
        if v != 0 {
            usage_units.insert(k.to_string(), v);
        }
    }
    busbar_substrate::billing::Usage { usage_units }
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
    host: &Arc<dyn EngineHost>,
    sink: &UsageSink,
    lane: &crate::engine::Lane,
    usage: Option<&busbar_substrate::billing::TokenUsage>,
    tier: &busbar_substrate::billing::Usage,
) {
    // Ledger the TIER SPLIT (uncached input / output / cache-read / cache-write — each prices
    // differently under the rate card) against the key's budget chain, in the SAME window as the
    // flat per-request fee (`sink.charged_at`, the header-arrival epoch), so token accrual and the
    // per-request fee never split across windows (#29). `meter_ledger` no-ops on an all-zero tier.
    // Routed through the host seam over the sink's opaque `GovHandle`/`CostHandle` — byte-identical to
    // the pre-flip `sink.gov.record_usage(&sink.cost, …)`.
    host.meter_ledger(
        &sink.gov,
        &sink.cost,
        &sink.key,
        &sink.pool,
        &lane.model,
        tier,
        sink.charged_at,
    );
    // Metering (raw per-model consumption series, token SPLIT preserved) — even a zero-token
    // delivered response counts its request. Same pinned epoch as the budget charges (#29).
    host.meter_series(
        &sink.gov,
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
    host: &Arc<dyn EngineHost>,
    usage: &busbar_substrate::billing::TokenUsage,
    usage_sink: &Option<UsageSink>,
    lane: Option<&crate::engine::Lane>,
) {
    if let Some(sink) = usage_sink {
        let Some(lane) = lane else { return };
        ledger_and_meter(host, sink, lane, Some(usage), &tier_usage(usage));
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
pub(crate) fn metric_pool_label<'a>(
    rt: &'a Arc<NativeRuntime>,
    pool_name: &'a str,
    i: usize,
) -> &'a str {
    if pool_name.is_empty() {
        EngineTables::new(rt).lanes()[i].model.as_str()
    } else {
        pool_name
    }
}

/// Emit `BREAKER_TRIPS_TOTAL` once for a logical Closed→Open trip on a (pool, lane) cell. Called from
/// the organic forward path's failure-record sites whenever `record_transient_in`/`record_rate_limit_in`
/// reports a fresh trip, mirroring the HardDown arm so threshold-based trips are counted too (#29). The
/// `pool` label is the bounded, operator-controlled canonical pool name, or the routed model name for
/// the default (`""`) cell (see `metric_pool_label`) so it correlates with REQUESTS_TOTAL.
pub(crate) fn emit_breaker_trip(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    pool_name: &str,
    i: usize,
) {
    // App-retype WEDGE 3: route the trip metric through the neutral host seam directly (the host is
    // already threaded through the forward loop — no per-call `engine_host_value` mint). Fired only on
    // a real Closed→Open trip, so it is off the steady-state hot path and the alloc gate.
    host.telemetry_breaker_trip(metric_pool_label(rt, pool_name, i), i);
    diag_warn!(LANE_BREAKER_TRIPPED, pool = %pool_name, lane = %EngineTables::new(rt).lanes()[i].model, "lane breaker tripped (Closed→Open)");
}

/// The effective per-attempt time-to-response-headers cap for pool member `i`: the pool-member
/// override wins over the model-level default (`None` = uncapped). This is the layering the
/// feature promises — the SAME model can be `attempt_timeout_ms: 10000` in a batch pool and
/// `50` in a latency-critical pool, with the model-level value as the fallback for pools (and
/// the default `""` cell) that don't override it.
pub(crate) fn effective_attempt_timeout_ms(
    cands: &[crate::engine::WeightedLane],
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
    cands: &[crate::engine::WeightedLane],
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
