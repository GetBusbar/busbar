// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::OnceLock;

use crate::diagnostics::diag_warn;
use crate::state::App;

mod money;

pub(crate) mod hooks;

mod source;

#[cfg(test)]
pub use source::Source;

use std::collections::HashMap;
use std::sync::RwLock;

const CACHE_KEY_SEP: char = '\u{1f}';

static REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> = OnceLock::new();
static DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> = OnceLock::new();

static PLANE_REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> =
    OnceLock::new();
static PLANE_DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> =
    OnceLock::new();

pub(crate) fn incr_requests_total(ingress_protocol: &str, pool: &str, outcome: &'static str) {
    let key = || format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}{CACHE_KEY_SEP}{outcome}");
    let make = || {
        metrics::counter!(
            REQUESTS_TOTAL,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string(),
            "outcome" => outcome
        )
    };
    with_handle(&REQUESTS_HANDLES, key, make, |h| h.increment(1));
}

pub(crate) fn incr_plane_requests_total(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
) {
    let key = || {
        format!(
            "{plane}{CACHE_KEY_SEP}{ingress_protocol}{CACHE_KEY_SEP}{pool}{CACHE_KEY_SEP}{outcome}"
        )
    };
    let make = || {
        metrics::counter!(
            PLANE_REQUESTS_TOTAL,
            "plane" => plane.to_string(),
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string(),
            "outcome" => outcome
        )
    };
    with_handle(&PLANE_REQUESTS_HANDLES, key, make, |h| h.increment(1));
}

pub(crate) fn record_request_duration(ingress_protocol: &str, pool: &str, seconds: f64) {
    let key = || format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}");
    let make = || {
        metrics::histogram!(
            REQUEST_DURATION_SECONDS,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string()
        )
    };
    with_handle(&DURATION_HANDLES, key, make, |h| h.record(seconds));
}

pub(crate) fn record_plane_request_duration(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    seconds: f64,
) {
    let key = || format!("{plane}{CACHE_KEY_SEP}{ingress_protocol}{CACHE_KEY_SEP}{pool}");
    let make = || {
        metrics::histogram!(
            PLANE_REQUEST_DURATION_SECONDS,
            "plane" => plane.to_string(),
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string()
        )
    };
    with_handle(&PLANE_DURATION_HANDLES, key, make, |h| h.record(seconds));
}

fn with_handle<H>(
    cache: &OnceLock<RwLock<HashMap<Box<str>, H>>>,
    key: impl FnOnce() -> String,
    make: impl FnOnce() -> H,
    use_it: impl FnOnce(&H),
) {
    if !recorder_installed() {
        use_it(&make());
        return;
    }
    let cache = cache.get_or_init(|| RwLock::new(HashMap::new()));
    let key = key();
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        use_it(h);
        return;
    }
    let handle = make();
    use_it(&handle);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

pub fn refresh_scrape_gauges(app: &App) {
    let now = busbar_kernel::store::now();

    money::refresh_money_gauges(app, now);

    let mut snap_cache: std::collections::HashMap<usize, busbar_kernel::store::LaneSnapshot> =
        std::collections::HashMap::new();

    let view = app.engine_tables_view();
    for (pool_name, member_idxs) in view.pools() {
        metrics::gauge!(POOL_QUEUED, "pool" => pool_name.to_string())
            .set(view.queued_depth(pool_name) as f64);
        for lane_idx in member_idxs {
            let snap = snap_cache
                .entry(lane_idx)
                .or_insert_with(|| app.store.snapshot(lane_idx, now));

            let state_val = lane_state_value(
                app.store.breaker_state_snapshot_in(pool_name, lane_idx),
                app.store.cooldown_remaining_in(pool_name, lane_idx, now),
                now,
            );

            let lane_label = view
                .lane_view(lane_idx)
                .expect("pool member lane index is in range")
                .model
                .to_string();
            metrics::gauge!(
                LANE_STATE,
                "pool" => pool_name.to_string(),
                "lane" => lane_label.clone()
            )
            .set(state_val);

            let avail = app.store.classify(pool_name, lane_idx, now);
            emit_lane_gauges(pool_name, &lane_label, snap, &avail, now);
        }
    }

    for (model, lane_idx) in view.model_indices() {
        let snap = snap_cache
            .entry(lane_idx)
            .or_insert_with(|| app.store.snapshot(lane_idx, now));
        let state_val = lane_state_value(
            app.store.breaker_state_snapshot_in("", lane_idx),
            app.store.cooldown_remaining_in("", lane_idx, now),
            now,
        );
        let lane_model = view
            .lane_view(lane_idx)
            .expect("the routed lane index is in range")
            .model
            .to_string();
        metrics::gauge!(
            LANE_STATE,
            "pool" => model.to_string(),
            "lane" => lane_model.clone()
        )
        .set(state_val);

        let avail = app.store.classify("", lane_idx, now);
        emit_lane_gauges(model, &lane_model, snap, &avail, now);
    }
}

fn lane_state_value(
    state: busbar_kernel::store::BreakerState,
    cooldown_remaining: u64,
    now: u64,
) -> f64 {
    use busbar_kernel::store::BreakerState;
    match state {
        BreakerState::HalfOpen => 1.0,
        BreakerState::Open { until } if until > now => 2.0,
        _ if cooldown_remaining > 0 => 2.0,
        _ => 0.0,
    }
}

fn emit_lane_gauges(
    pool_label: &str,
    lane_label: &str,
    snap: &busbar_kernel::store::LaneSnapshot,
    avail: &Result<(), busbar_kernel::store::Unavailable>,
    now: u64,
) {
    let pool_l = metrics::Label::new("pool", pool_label.to_string());
    let lane_l = metrics::Label::new("lane", lane_label.to_string());
    metrics::gauge!(LANE_AVAILABLE, vec![pool_l.clone(), lane_l.clone()]).set(if avail.is_ok() {
        1.0
    } else {
        0.0
    });

    let hint_ms = avail
        .as_ref()
        .err()
        .and_then(|u| u.recovery_hint_ms(now))
        .unwrap_or(0);
    metrics::gauge!(LANE_RECOVERY_HINT_MS, vec![pool_l.clone(), lane_l.clone()])
        .set(hint_ms as f64);
    metrics::gauge!(LANE_INFLIGHT, vec![pool_l.clone(), lane_l.clone()]).set(snap.inflight as f64);
    if let Some(available) = snap.available {
        metrics::gauge!(LANE_AVAILABLE_PERMITS, vec![pool_l, lane_l]).set(available as f64);
    }
}

#[cfg(test)]
#[path = "../tests/metrics_tests.rs"]
mod tests;

pub const ROUTE_POLICY_SELECTIONS_TOTAL: &str = "busbar_route_policy_selections_total";

pub const ROUTE_POLICY_REJECTIONS_TOTAL: &str = "busbar_route_policy_rejections_total";

pub const HOOK_CONTENT_TRUNCATED_TOTAL: &str = "busbar_hook_content_truncated_total";

pub const BILLING_TRUNCATED_TOTAL: &str = "busbar_billing_truncated_total";

pub const PLUGIN_OBSERVATIONS_DROPPED_TOTAL: &str = "busbar_plugin_observations_dropped_total";

pub const JOURNAL_QUARANTINED_TOTAL: &str = "busbar_journal_quarantined_total";

use busbar_contract::export_calls::Family;
use std::time::Duration;

use crate::diag_error;
use crate::diagnostics::{
    METRICS_MAINTENANCE_THREAD_SPAWN_FAILED, METRICS_RECORDER_INSTALL_FAILED,
};

static HANDLE: OnceLock<Option<&'static source::Source>> = OnceLock::new();

static SOURCE: OnceLock<source::Source> = OnceLock::new();

static ENABLED: OnceLock<bool> = OnceLock::new();

pub fn enabled() -> bool {
    ENABLED.get().copied().unwrap_or(false)
}

#[path = "../observe.rs"]
pub mod observe;

pub fn configure(buffer: Option<Duration>) {
    let _ = ENABLED.set(buffer.is_some());
    if let Some(buffer) = buffer {
        std::thread::spawn(move || init_with(buffer));
    }
}

#[inline]
pub fn retaining() -> bool {
    retaining_from(HANDLE.get().map(Option::is_some), enabled)
}

pub fn retaining_from(handle_installed: Option<bool>, opted_in: impl FnOnce() -> bool) -> bool {
    match handle_installed {
        Some(installed) => installed,
        None => opted_in(),
    }
}

pub const REQUESTS_TOTAL: &str = "busbar_requests_total";

pub use crate::telemetry::{UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL};
pub const BREAKER_TRIPS_TOTAL: &str = "busbar_breaker_trips_total";
pub const FAILOVERS_TOTAL: &str = "busbar_failovers_total";
pub const REQUEST_DURATION_SECONDS: &str = "busbar_request_duration_seconds";
pub const TRANSLATIONS_TOTAL: &str = "busbar_translations_total";

pub const PLANE_REQUESTS_TOTAL: &str = "busbar_plane_requests_total";
pub const PLANE_REQUEST_DURATION_SECONDS: &str = "busbar_plane_request_duration_seconds";

pub const BILLING_TAP_DECODE_FAIL_TOTAL: &str = "busbar_billing_tap_decode_fail_total";

pub fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
    metrics::counter!(
        BILLING_TAP_DECODE_FAIL_TOTAL,
        "protocol" => protocol.to_string(),
        "reason" => reason,
    )
    .increment(1);
    static SEEN: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    seen.insert(format!("{protocol}:{reason}"))
}

pub fn usage_tap_fault(protocol: &str, reason: &'static str) {
    if usage_tap_decode_fail_should_warn(protocol, reason) {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage could not be read; \
             billing 0 tokens for this request"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage still could not be read; \
             billing 0 tokens for this request"
        );
    }
}

pub const ADMISSION_DENIED_TOTAL: &str = "busbar_admission_denied_total";

pub const METERING_PENDING_COALESCED_TOTAL: &str = "busbar_metering_pending_coalesced_total";

pub const PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL: &str =
    "busbar_plugin_request_headers_truncated_total";

pub const PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL: &str =
    "busbar_plugin_response_headers_rejected_total";

pub const PLUGIN_LABEL_REFUSED_TOTAL: &str = "busbar_plugin_label_refused_total";

pub const KEY_SPEND_CENTS: &str = "busbar_key_spend_cents";

pub const KEY_TOKENS_TOTAL: &str = "busbar_key_tokens_total";

pub const BUCKET_TOKENS: &str = "busbar_bucket_tokens";

pub const BUCKET_SPEND_CENTS: &str = "busbar_bucket_spend_cents";

pub const BUCKET_BUDGET_REMAINING_CENTS: &str = "busbar_bucket_budget_remaining_cents";

pub const LANE_STATE: &str = "busbar_lane_state";

pub const LANE_AVAILABLE: &str = "busbar_lane_available";

pub const LANE_RECOVERY_HINT_MS: &str = "busbar_lane_recovery_hint_ms";

pub const LANE_INFLIGHT: &str = "busbar_lane_inflight";

pub const LANE_AVAILABLE_PERMITS: &str = "busbar_lane_available_permits";

pub const POOL_QUEUED: &str = "busbar_pool_queued";

pub fn init_with(buffer: Duration) {
    let bucket = buffer
        .checked_div(SUMMARY_BUCKETS.get())
        .unwrap_or(buffer)
        .max(Duration::from_millis(1));

    HANDLE.get_or_init(|| {
        let source =
            SOURCE.get_or_init(|| source::Source::new(bucket, SUMMARY_BUCKETS, GAUGE_IDLE_TIMEOUT));
        install(source, bucket)
    });
}

fn install(source: &'static source::Source, bucket: Duration) -> Option<&'static source::Source> {
    match metrics::set_global_recorder(source) {
        Ok(()) => {
            describe();

            metrics::counter!(BILLING_TRUNCATED_TOTAL).absolute(0);

            spawn_maintenance(bucket);
            Some(source)
        }
        Err(e) => {
            diag_error!(
                METRICS_RECORDER_INSTALL_FAILED,
                "{}: {e}",
                crate::config::migration_table::text("snapshot_recorder_failed")
            );
            None
        }
    }
}

const SUMMARY_BUCKETS: std::num::NonZeroU32 = match std::num::NonZeroU32::new(3) {
    Some(n) => n,
    None => unreachable!(),
};

pub const GAUGE_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Install the real recorder for a test-support caller with an explicit retention window.
/// Production uses [`init_with`] with the operator's configured `buffer_seconds`.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn init_for_test(buffer: Duration) {
    let _ = ENABLED.set(true);
    init_with(buffer);
}

pub fn drain_pending() {
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();

    let Some(Some(source)) = HANDLE.get() else {
        return;
    };

    crate::telemetry::flush_to_recorder();

    source.drain();
}

fn spawn_maintenance(interval: Duration) {
    let spawned = std::thread::Builder::new()
        .name("busbar-metrics-drain".into())
        .spawn(move || loop {
            std::thread::sleep(interval);
            drain_pending();
        });
    if let Err(e) = spawned {
        diag_warn!(
            METRICS_MAINTENANCE_THREAD_SPAWN_FAILED,
            error = %e,
            "could not spawn the metrics maintenance thread; buffered observations now drain only \
             on a /metrics scrape"
        );
    }
}

fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_counter!(
        REQUESTS_TOTAL,
        "Total ingress requests, by ingress protocol, pool, and outcome"
    );
    describe_counter!(
        PLANE_REQUESTS_TOTAL,
        "Total mounted-plane requests, by plane, ingress protocol, pool, and outcome"
    );
    describe_counter!(
        UPSTREAM_ATTEMPTS_TOTAL,
        "Upstream call attempts, by pool and lane"
    );
    describe_counter!(
        UPSTREAM_FAILURES_TOTAL,
        "Upstream failures, by pool, lane, and breaker disposition"
    );
    describe_counter!(
        BREAKER_TRIPS_TOTAL,
        "Circuit-breaker trips, by pool and lane"
    );
    describe_counter!(FAILOVERS_TOTAL, "Failover events, by pool and reason");
    describe_counter!(
        ROUTE_POLICY_SELECTIONS_TOTAL,
        "Requests whose routing policy produced a ranked order, by policy name and pool"
    );
    describe_counter!(
        ROUTE_POLICY_REJECTIONS_TOTAL,
        "Requests deliberately rejected by the routing policy's reject verb, by policy name, pool, and status"
    );
    describe_counter!(
        TRANSLATIONS_TOTAL,
        "Cross-protocol translations, by source and target protocol"
    );
    describe_counter!(
        BILLING_TAP_DECODE_FAIL_TOTAL,
        "Same-protocol 2xx bodies the usage tap could not decode (billed 0 tokens), by protocol and reason"
    );
    describe_counter!(
        METERING_PENDING_COALESCED_TOTAL,
        "Metering cells coalesced into a per-bucket overflow sentinel because the write-behind accumulator was at its cap (sustained store outage); totals preserved, per-key attribution collapsed"
    );
    describe_histogram!(
        REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "End-to-end request duration in seconds"
    );
    describe_histogram!(
        PLANE_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "End-to-end mounted-plane request duration in seconds, by plane"
    );

    describe_gauge!(
        KEY_SPEND_CENTS,
        Unit::Count,
        "Per-virtual-key accumulated spend in cents for the current budget window (scrape-time)"
    );
    describe_gauge!(
        BUCKET_TOKENS,
        "Per-(bucket, model, tier) tokens in the bucket's current budget window (key and budget-group buckets; derived from the token ledger at scrape time)"
    );
    describe_gauge!(
        BUCKET_SPEND_CENTS,
        Unit::Count,
        "Derived spend (abstract minor units) per budget-group bucket for its current window, recomputed from the token ledger x the current rate card at scrape time"
    );
    describe_gauge!(
        BUCKET_BUDGET_REMAINING_CENTS,
        Unit::Count,
        "Budget-group cap minus derived spend for the current window"
    );
    describe_gauge!(
        KEY_TOKENS_TOTAL,
        Unit::Count,
        "Per-virtual-key accumulated tokens consumed in the current budget window (scrape-time)"
    );
    describe_gauge!(
        LANE_STATE,
        Unit::Count,
        "Per-(pool,lane) circuit-breaker health: 0=healthy, 1=half-open, 2=tripped (scrape-time)"
    );
    describe_gauge!(
        LANE_AVAILABLE,
        Unit::Count,
        "Per-(pool,lane) availability from the shared classify taxonomy: 1 = would admit, 0 = unavailable for any reason (breaker/capacity/dead/budget) (scrape-time)"
    );
    describe_gauge!(
        LANE_RECOVERY_HINT_MS,
        Unit::Milliseconds,
        "Per-(pool,lane) honest lower bound (ms) on when an unavailable lane could next serve; 0 when available or no self-recovery basis (scrape-time)"
    );
    describe_gauge!(
        LANE_INFLIGHT,
        Unit::Count,
        "Per-(pool,lane) in-flight requests (held concurrency permits) (scrape-time)"
    );
    describe_gauge!(
        LANE_AVAILABLE_PERMITS,
        Unit::Count,
        "Per-(pool,lane) available concurrency permits for a BOUNDED lane (scrape-time; unbounded lanes emit no sample)"
    );
    describe_gauge!(
        POOL_QUEUED,
        Unit::Count,
        "Per-pool requests currently parked in the on_exhausted queue bounded wait (scrape-time)"
    );
}

#[inline]
pub fn recorder_installed() -> bool {
    matches!(HANDLE.get(), Some(Some(_)))
}

pub fn snapshot() -> Option<Vec<Family>> {
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    let source = (*HANDLE.get()?)?;
    crate::telemetry::flush_to_recorder();
    Some(source.snapshot())
}
