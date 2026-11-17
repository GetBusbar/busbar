// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::OnceLock;

use crate::diagnostics::diag_warn;
use crate::state::App;

mod money;

pub mod catalogue;
mod source;

pub(crate) use source::request_store;

pub use source::{boot_nonce, process_generation, RequestIdentity, RequestSnapshot};

#[cfg(test)]
pub use source::Source;

// The bank misses below (labels the bind-time `AppSlots` did not register: custom protocols, a pool
// from another generation, a bare test `App`) emit through the recorder uncached. The keyed handle
// cache they used before built a `format!` key per call and grew without bound; the registered
// series are banked in `telemetry::AppSlots`, so nothing on the request path needs it.

pub(crate) fn incr_requests_total(ingress_protocol: &str, pool: &str, outcome: &'static str) {
    metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    )
    .increment(1);
}

pub(crate) fn incr_plane_requests_total(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
) {
    metrics::counter!(
        PLANE_REQUESTS_TOTAL,
        "plane" => plane.to_string(),
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    )
    .increment(1);
}

pub(crate) fn record_request_duration(ingress_protocol: &str, pool: &str, seconds: f64) {
    metrics::histogram!(
        REQUEST_DURATION_SECONDS,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    )
    .record(seconds);
}

pub(crate) fn record_plane_request_duration(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    seconds: f64,
) {
    metrics::histogram!(
        PLANE_REQUEST_DURATION_SECONDS,
        "plane" => plane.to_string(),
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    )
    .record(seconds);
}

pub async fn refresh_scrape_gauges(app: &App) -> Result<(), &'static str> {
    let now = busbar_kernel::store::now();

    // Persistence outages must not suppress the independent in-memory lane gauges.
    let money_result = money::refresh_money_gauges(app, now).await;

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
    money_result
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

pub const HOOK_PROJECT_OVER_CAP_TOTAL: &str = "busbar_hook_project_over_cap_total";

pub const BILLING_TRUNCATED_TOTAL: &str = "busbar_billing_truncated_total";

pub const PLUGIN_OBSERVATIONS_DROPPED_TOTAL: &str = "busbar_plugin_observations_dropped_total";

pub const PLUGIN_TEXT_CUT_TOTAL: &str = "busbar_plugin_text_cut_total";

/// Plugin inspections refused because the process opened its cap of distinct images for inspection (DES-443 r3).
pub const PLUGIN_INSPECT_CAP_REFUSALS_TOTAL: &str = "busbar_plugin_inspect_cap_refusals_total";

/// How long the one plugin inspection slot has been held, in seconds (0 when free; DES-443 r3).
pub const PLUGIN_INSPECT_SLOT_HELD_SECONDS: &str = "busbar_plugin_inspect_slot_held_seconds";

pub const JOURNAL_QUARANTINED_TOTAL: &str = "busbar_journal_quarantined_total";

/// Request-log webhook deliveries shed under backpressure; a plane may carry it (DES-337).
pub const WEBHOOK_LOGS_DROPPED_TOTAL: &str = "busbar_webhook_logs_dropped_total";

/// Request-log file appends shed under backpressure; a plane may carry it (DES-337).
pub const FILE_LOGS_DROPPED_TOTAL: &str = "busbar_file_logs_dropped_total";

/// Terminal audit originals refused before native confirmation (no labels).
pub const AUDIT_STAGE_FAILURES_TOTAL: &str = "busbar_audit_stage_failures_total";
pub const EXPORT_DROPPED_TOTAL: &str = "busbar_export_dropped_total";
pub const EXPORT_CAPTURE_REFUSALS_TOTAL: &str = "busbar_export_capture_refusals_total";
pub const EXPORT_INTEGRITY_FAILURES_TOTAL: &str = "busbar_export_audit_integrity_failures_total";
pub const EXPORT_HELD_LINES: &str = "busbar_export_held_lines";

/// Finished governed units whose spend still awaits settlement in the store (the admission gate's
/// terminal backlog, SHUTDOWN-HANG F4a); `governance::drain::MAX_PENDING_CHECKPOINTS` caps it.
pub const UNIT_CHECKPOINTS_TERMINAL: &str = "busbar_unit_checkpoints_terminal";

/// Governed admissions alive (an admission grant not yet released after its unit's terminal
/// checkpoint was staged; SHUTDOWN-HANG F4a).
pub const GOVERNED_ADMISSIONS_LIVE: &str = "busbar_governed_admissions_live";

/// Store slot-queue gauge; `state` is free, in_flight, in_doubt, resolved_uncollected or reconcile,
/// and the states add up to `pending_operations` (STORE-TRANSACTIONS §2.7).
pub const STORE_SLOTS: &str = "busbar_store_slots";

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

static EXPLICITLY_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The recorder retention a deployment runs with: the registry is ON by default (`telemetry.enabled`,
/// whatever the exports are), and an export recorder only raises the retention. An explicit
/// `enabled: false` leaves only what an export recorder itself asks for.
#[must_use]
pub fn retention_for(
    enabled: bool,
    retention_seconds: u64,
    export: Option<Duration>,
) -> Option<Duration> {
    if !enabled {
        return export;
    }
    let own = Duration::from_secs(retention_seconds.max(1));
    Some(export.map_or(own, |export| export.max(own)))
}

/// Configure the registry from the `telemetry:` block and the resolved export recorder.
pub fn configure_telemetry(telemetry: &crate::config::TelemetryCfg, export: Option<Duration>) {
    EXPLICITLY_OFF.store(!telemetry.enabled, std::sync::atomic::Ordering::Relaxed);
    crate::telemetry::set_max_lane_series(telemetry.max_lane_series);
    configure(retention_for(
        telemetry.enabled,
        telemetry.retention_seconds,
        export,
    ));
}

/// Whether the operator set `telemetry.enabled: false`: `/metrics` answers 503 `telemetry_disabled`.
#[must_use]
pub fn explicitly_off() -> bool {
    EXPLICITLY_OFF.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn configure(buffer: Option<Duration>) {
    // Complete off-path arena construction before a phase emitter can see effective retention.
    if buffer.is_some() {
        let _ = request_store::process();
    }
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
/// Needs admitted under an instance's `insecure_transport.accept` (DES-359 r3 L2).
pub const INSECURE_TRANSPORT_ADMITTED_TOTAL: &str = "busbar_insecure_transport_admitted_total";

pub const PLANE_REQUESTS_TOTAL: &str = "busbar_plane_requests_total";
pub const PLANE_REQUEST_DURATION_SECONDS: &str = "busbar_plane_request_duration_seconds";

/// Per-lane request duration; labels `pool`, `target`, `model`, `instance`, attached at build from the
/// lane table, never from the request.
pub const LANE_REQUEST_DURATION_SECONDS: &str = "busbar_lane_request_duration_seconds";

/// Units that did not complete, by closed unit `reason` and `instance`.
pub const UNIT_REFUSALS_TOTAL: &str = "busbar_unit_refusals_total";

/// Build identity: a gauge fixed at 1, labelled `version` (ADMIN-API 1.6 section 12).
pub const BUILD_INFO: &str = "busbar_build_info";

pub const BILLING_TAP_DECODE_FAIL_TOTAL: &str = "busbar_billing_tap_decode_fail_total";

pub(crate) fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
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
             billing follows the plane's usage policy"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage still could not be read; \
             billing follows the plane's usage policy"
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

pub const TELEMETRY_OVERFLOW_REPLAYS_TOTAL: &str = "busbar_telemetry_overflow_replays_total";

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
    #[cfg(test)]
    if let Some((entered, release)) = INSTALL_TEST_GATE.get() {
        entered.wait();
        release.wait();
    }
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
                "the metrics recorder install failed; the metrics route will be empty: {e}"
            );
            None
        }
    }
}

#[cfg(test)]
static INSTALL_TEST_GATE: OnceLock<(std::sync::Barrier, std::sync::Barrier)> = OnceLock::new();

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
    let _ = request_store::process();
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

/// Help and unit for every catalogued family, from [`catalogue::HOST_METRICS`] (DES-337).
fn describe() {
    metrics::with_recorder(|recorder| {
        for d in catalogue::HOST_METRICS {
            let (name, help) = (d.name.into(), d.help.into());
            match d.kind {
                catalogue::Kind::Counter => recorder.describe_counter(name, d.unit, help),
                catalogue::Kind::Gauge => recorder.describe_gauge(name, d.unit, help),
                catalogue::Kind::Histogram => recorder.describe_histogram(name, d.unit, help),
            }
        }
    });
}

#[inline]
pub fn recorder_installed() -> bool {
    matches!(HANDLE.get(), Some(Some(_)))
}

pub fn snapshot() -> Option<Vec<Family>> {
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    let Some(Some(source)) = HANDLE.get() else {
        request_store::unavailable();
        return None;
    };
    crate::telemetry::flush_to_recorder();
    source.snapshot()
}

/// Bounded request-phase telemetry for an authorized internal reader. Missing/failed recorder
/// initialization is unavailable, never an invented zero snapshot.
pub fn request_snapshot(limit: usize) -> Option<RequestSnapshot> {
    let Some(Some(source)) = HANDLE.get() else {
        request_store::unavailable();
        return None;
    };
    source.request_snapshot(limit)
}

/// Covered projection/serialization storage is separate from recorder maintenance and workspace.
pub fn snapshot_budgeted(
    request: &crate::limits::process_admission::RequestLease,
) -> Result<Option<crate::limits::output::Captured<Vec<Family>>>, crate::limits::output::OutputError>
{
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    let Some(Some(source)) = HANDLE.get() else {
        request_store::unavailable();
        return Ok(None);
    };
    crate::telemetry::flush_to_recorder();
    source.snapshot_budgeted(request)
}

/// The owned exact result keeps output credit after the recorder workspace becomes reusable.
/// This is an internal producer, not a new Admin endpoint or authorization grant.
pub fn request_snapshot_budgeted(
    limit: usize,
    request: &crate::limits::process_admission::RequestLease,
) -> Result<
    Option<crate::limits::output::Captured<RequestSnapshot>>,
    crate::limits::output::OutputError,
> {
    let Some(Some(source)) = HANDLE.get() else {
        request_store::unavailable();
        return Ok(None);
    };
    source.request_snapshot_budgeted(limit, request)
}
