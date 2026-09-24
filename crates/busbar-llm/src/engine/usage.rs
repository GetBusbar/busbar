use super::*;

use busbar_substrate_values::diag_warn;
use busbar_substrate_values::diagnostics::LANE_BREAKER_TRIPPED;

/// Charge a non-streaming response's token usage to the virtual key's budget, sourced from the
/// IR. The streaming path bills from `translate.usage()` inside `FirstByteBody`; buffered
/// (non-streaming) cross-protocol responses already decode the egress body egress→IR→ingress, so the
/// terminal `IrUsage` is available WITHOUT a separate byte-scan — bill straight from `ir.usage`.
///
/// Billed tokens = the normalized billable total: `uncached_input + cache_read +
/// cache_creation + output` (see [`busbar_substrate_values::ir::IrUsage::billable_tokens`]). Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so this sum is correct
/// provider-agnostically. This matches the streaming billing arm.
/// OPERATION-BLIND usage recording: project the response IR's neutral `Billing` and record token
/// meters through the existing sink (identical numbers for chat — the Billing round-trip preserves
/// the additive-cache convention). Non-token meters (duration/characters/images/flat) are carried in
/// the client-visible body today and priced by the 1.3 engine; nothing to record here yet.
pub(crate) fn record_resp_usage(
    host: &Arc<dyn EngineHost>,
    usage: Option<busbar_substrate_values::billing::Billing>,
    usage_sink: &Option<UsageSink>,
    lane: Option<&crate::engine::Lane>,
) {
    if let Some(busbar_substrate_values::billing::Billing::Tokens(t)) = usage {
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
            // ITEM 134: a COUNTED non-token unit (a rerank's search units) is ledgered VERBATIM as
            // its open class (#71) against the key's budget chain, in the fee's window — where the
            // card prices it; a present card silent about it refuses (#42); an absent card reads 0.
            // The metering row below is untouched: the request counts with no token split.
            //
            // The class map is [`open_units_of`]'s — the SAME map the tap reports back for the
            // durable book (#71), so the two books are handed one set of counts from one function.
            if let Some(busbar_substrate_values::billing::Billing::Counted { .. }) = &usage {
                let usage_units = open_units_of(&usage);
                host.meter_ledger(
                    &sink.pin,
                    &sink.key,
                    &sink.pool,
                    &lane.model,
                    &busbar_substrate_values::billing::Usage { usage_units },
                    sink.charged_at,
                );
            }
            host.meter_series(
                sink.pin.gov(),
                &sink.key.id,
                &lane.model,
                &lane.provider,
                None,
                sink.charged_at,
            );
        }
    }
}

/// **EVERY OPEN CLASS a delivery billed**, as the class map it is ledgered under (#71): a COUNTED
/// non-token unit (a rerank's search units, item 134) VERBATIM as its open class, and nothing for any
/// other shape.
///
/// ONE function, read twice: [`record_resp_usage`] ledgers exactly this map onto the governance
/// ledger, and the buffered tap reports exactly this map back
/// ([`crate::engine::TapReport::open_units`]) so the late reading hands the durable (second) book
/// the same counts. Two spellings of this projection are how the two books came to disagree.
///
/// Every variant is spelled, as in the tap's token projection: `Billing` is closed, and a wildcard
/// here would quietly report nothing for a counted shape added after this was written. The token
/// split rides [`crate::engine::TapReport::usage`]; duration, characters, images and the flat fee are
/// not ledgered as a class today, so reporting one here would put a count on the durable book the
/// governance ledger does not hold.
pub(crate) fn open_units_of(
    usage: &Option<busbar_substrate_values::billing::Billing>,
) -> std::collections::BTreeMap<String, u64> {
    use busbar_substrate_values::billing::Billing;
    match usage {
        Some(Billing::Counted { class, count }) => {
            std::collections::BTreeMap::from([(class.clone(), *count)])
        }
        Some(Billing::Tokens(_))
        | Some(Billing::Duration { .. })
        | Some(Billing::Characters { .. })
        | Some(Billing::Images { .. })
        | Some(Billing::Flat)
        | None => std::collections::BTreeMap::new(),
    }
}

/// Project the IR's normalized usage into the neutral name-keyed [`busbar_substrate_values::billing::Usage`]
/// carrier: the four reserved units (`input`/`output`/`cache_read`/`cache_write`) as canonical map
/// keys (M1b — `TierTokens` is dissolved). Readers normalize `input_tokens` to UNCACHED and keep the
/// cache fields ADDITIVE, so the mapping is direct: cache-creation is the `cache_write` unit. Zero
/// tiers are omitted so the map stays sparse (no-zero-entry).
pub(crate) use busbar_llm_codec::wire_shim::tier_usage;

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
    usage: Option<&busbar_substrate_values::billing::TokenUsage>,
    tier: &busbar_substrate_values::billing::Usage,
) {
    // Ledger the TIER SPLIT (uncached input / output / cache-read / cache-write — each prices
    // differently under the rate card) against the key's budget chain, in the SAME window as the
    // flat per-request fee (`sink.charged_at`, the header-arrival epoch), so token accrual and the
    // per-request fee never split across windows (#29). `meter_ledger` no-ops on an all-zero tier.
    // Routed through the host seam over the sink's opaque meter pin — byte-identical to the pre-flip
    // `sink.gov.record_usage(&sink.cost, …)`.
    host.meter_ledger(
        &sink.pin,
        &sink.key,
        &sink.pool,
        &lane.model,
        tier,
        sink.charged_at,
    );
    // Metering (raw per-model consumption series, token SPLIT preserved) — even a zero-token
    // delivered response counts its request. Same pinned epoch as the budget charges (#29).
    //
    // THE ROW IS WRITTEN UNCONDITIONALLY (DECISION #43, owner ruling 2026-09-22: "planes always
    // ledger"). The plane hands its counts over with no branch and no knowledge of billing state, and
    // nothing between here and the series asks either: with no `rate_card:` the row is still the
    // record of what the plane did, and BILLING OFF is the money VIEW reading it as 0 (#42), never a
    // missing row. This used to route through the kernel's `meter_series_billed`, which dropped the
    // row whenever the pinned card was absent — the same card-gated write item 36 removed from the
    // MCP/A2A charge (0ee95aafd). The flat/counted arm of `record_resp_usage` above already wrote its
    // row this way; the token arm now matches it. The budget/ledger accrual ABOVE is not switched
    // either: token-COUNT rate caps enforce off that accrual, and #42 keeps admission, concurrency and
    // breaker on for an unbilled plane.
    host.meter_series(
        sink.pin.gov(),
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
    usage: &busbar_substrate_values::billing::TokenUsage,
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

#[cfg(test)]
#[path = "tests/rerank_search_units_tests.rs"]
mod rerank_search_units_tests;
