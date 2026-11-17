// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST METRIC CATALOGUE (DES-337, OBS-4): one declared row per `busbar_` family the host
//! emits or lets a plane carry on its behalf. Every consumer derives from it: [`super::describe`]
//! (help and unit), the plugin series reservation (`root::linked::host_series`), the plane-carried
//! list the metric-family guard enforces ([`plane_carried_series`]) and the metrics table in
//! docs/observability.md. A new family is one row here, next to its existing name constant.

use metrics::Unit;

use super::source::request_store::{
    TELEMETRY_REQUEST_CAPTURE_REFUSALS_TOTAL, TELEMETRY_REQUEST_CELLS,
    TELEMETRY_REQUEST_RESERVED_BYTES,
};
use super::source::{
    REQUEST_BIN, REQUEST_CLIENT_ERRORS, REQUEST_COUNT, REQUEST_ERRORS, REQUEST_SUM,
};
use super::*;
use crate::auth::login_limits::{LOGIN_ATTEMPTS_TOTAL, LOGIN_THROTTLED_TOTAL};
use crate::hooks::taps::TAP_NOTIFICATIONS_DROPPED_TOTAL;
use crate::off_path::governance::persistence::prices::runtime::CARD_ALARMS_TOTAL;
use crate::telemetry::{REQUEST_PHASE_DROPPED, REQUEST_PHASE_DURATION};

/// A family's exposition type. No `Summary`: the host emits none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    /// The exposition type word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One host metric family.
#[derive(Clone, Copy, Debug)]
pub struct MetricDecl {
    /// The family name: the emitting module's own name constant.
    pub name: &'static str,
    pub kind: Kind,
    /// The fixed label keys every series of the family carries, in emission order. Mint labels on
    /// the key and key-bucket gauges are operator-chosen and not listed (their help says so).
    pub labels: &'static [&'static str],
    pub unit: Option<Unit>,
    pub help: &'static str,
    /// A plane may emit this family on core's behalf, with exactly [`Self::labels`] (the
    /// metric-family guard, `busbar_contract::plane::check_metric_families`).
    pub plane_carried: bool,
}

const fn row(
    name: &'static str,
    kind: Kind,
    labels: &'static [&'static str],
    unit: Option<Unit>,
    help: &'static str,
) -> MetricDecl {
    MetricDecl {
        name,
        kind,
        labels,
        unit,
        help,
        plane_carried: false,
    }
}

const fn carried(
    name: &'static str,
    labels: &'static [&'static str],
    help: &'static str,
) -> MetricDecl {
    MetricDecl {
        name,
        kind: Kind::Counter,
        labels,
        unit: None,
        help,
        plane_carried: true,
    }
}

use Kind::{Counter, Gauge, Histogram};

/// Every host metric family.
pub const HOST_METRICS: &[MetricDecl] = &[
    // Requests and routing.
    carried(
        REQUESTS_TOTAL,
        &["ingress_protocol", "pool", "outcome"],
        "Total ingress requests, by ingress protocol, pool, and outcome",
    ),
    row(
        PLANE_REQUESTS_TOTAL,
        Counter,
        &["plane", "ingress_protocol", "pool", "outcome"],
        None,
        "Total mounted-plane requests, by plane, ingress protocol, pool, and outcome",
    ),
    row(
        REQUEST_DURATION_SECONDS,
        Histogram,
        &["ingress_protocol", "pool"],
        Some(Unit::Seconds),
        "End-to-end request duration in seconds",
    ),
    row(
        PLANE_REQUEST_DURATION_SECONDS,
        Histogram,
        &["plane", "ingress_protocol", "pool"],
        Some(Unit::Seconds),
        "End-to-end mounted-plane request duration in seconds, by plane",
    ),
    row(
        LANE_REQUEST_DURATION_SECONDS,
        Histogram,
        &["pool", "target", "model", "instance"],
        Some(Unit::Seconds),
        "Request duration in seconds by lane, labelled pool, target, model and instance",
    ),
    carried(
        UPSTREAM_ATTEMPTS_TOTAL,
        &["pool", "lane"],
        "Upstream call attempts, by pool and lane",
    ),
    carried(
        UPSTREAM_FAILURES_TOTAL,
        &["pool", "lane", "disposition"],
        "Upstream failures, by pool, lane, and breaker disposition",
    ),
    carried(
        BREAKER_TRIPS_TOTAL,
        &["pool", "lane"],
        "Circuit-breaker trips, by pool and lane",
    ),
    carried(
        FAILOVERS_TOTAL,
        &["pool", "reason"],
        "Failover events, by pool and reason",
    ),
    carried(
        ROUTE_POLICY_SELECTIONS_TOTAL,
        &["policy", "pool"],
        "Requests whose routing policy produced a ranked order, by policy name and pool",
    ),
    carried(
        ROUTE_POLICY_REJECTIONS_TOTAL,
        &["policy", "pool", "status"],
        "Requests deliberately rejected by the routing policy's reject verb, by policy name, pool, and status",
    ),
    carried(
        TRANSLATIONS_TOTAL,
        &["from", "to"],
        "Cross-protocol translations, by source and target protocol",
    ),
    row(
        UNIT_REFUSALS_TOTAL,
        Counter,
        &["reason", "instance"],
        None,
        "Units that did not complete, by closed reason and plane instance",
    ),
    row(
        INSECURE_TRANSPORT_ADMITTED_TOTAL,
        Counter,
        &["kind", "instance", "accept"],
        None,
        "Needs (OPEN, STARTTLS, FETCH) admitted under an instance's insecure_transport acceptance, by kind, instance and accept; pooled reuse included, not TCP dials",
    ),
    row(
        ADMISSION_DENIED_TOTAL,
        Counter,
        &["gate"],
        None,
        "Work refused by a bounded admission gate, by gate",
    ),
    // Request phases.
    row(
        REQUEST_PHASE_DURATION,
        Histogram,
        &["plane", "phase", "pool", "ingress_protocol", "outcome"],
        Some(Unit::Seconds),
        "Request phase duration observations, by plane, phase, pool, ingress protocol and outcome; exported as the request phase count, sum, error and bin counters",
    ),
    row(
        REQUEST_PHASE_DROPPED,
        Counter,
        &["reason"],
        None,
        "Request phase observations the bounded request store could not record, by reason",
    ),
    row(
        REQUEST_COUNT,
        Counter,
        &["plane", "phase", "pool", "ingress_protocol", "process_boot_nonce"],
        None,
        "Request phase observations, cumulative since the process booted",
    ),
    row(
        REQUEST_SUM,
        Counter,
        &["plane", "phase", "pool", "ingress_protocol", "process_boot_nonce"],
        Some(Unit::Microseconds),
        "Sum of request phase durations in microseconds, cumulative since the process booted",
    ),
    row(
        REQUEST_ERRORS,
        Counter,
        &["plane", "phase", "pool", "ingress_protocol", "process_boot_nonce"],
        None,
        "Request phase observations whose outcome was exhausted or error",
    ),
    row(
        REQUEST_CLIENT_ERRORS,
        Counter,
        &["plane", "phase", "pool", "ingress_protocol", "process_boot_nonce"],
        None,
        "Request phase observations whose outcome was client_error",
    ),
    row(
        REQUEST_BIN,
        Counter,
        &[
            "plane",
            "phase",
            "pool",
            "ingress_protocol",
            "process_boot_nonce",
            "upper_bound_ms",
        ],
        None,
        "Request phase observations per exclusive duration bin, by upper bound in milliseconds (+Inf for the last bin)",
    ),
    row(
        TELEMETRY_REQUEST_CAPTURE_REFUSALS_TOTAL,
        Counter,
        &["reason"],
        None,
        "Request telemetry captures refused, by reason",
    ),
    row(
        TELEMETRY_REQUEST_CELLS,
        Gauge,
        &["state"],
        None,
        "Request telemetry store cells, by state (reserved or observed)",
    ),
    row(
        TELEMETRY_REQUEST_RESERVED_BYTES,
        Gauge,
        &[],
        Some(Unit::Bytes),
        "Bytes reserved by the request telemetry store",
    ),
    row(
        TELEMETRY_OVERFLOW_REPLAYS_TOTAL,
        Counter,
        &[],
        None,
        "Full histogram buffers replayed into the recorder on the request thread because the slot already had two buffers parked or the 8 MiB park budget was spent",
    ),
    // Billing and metering.
    carried(
        BILLING_TRUNCATED_TOTAL,
        &[],
        "Same-protocol non-stream responses whose billing-side buffer hit the translate-body cap before the usage block, so the request billed zero tokens",
    ),
    carried(
        BILLING_TAP_DECODE_FAIL_TOTAL,
        &["protocol", "reason"],
        "Same-protocol 2xx bodies the usage tap could not decode (billed 0 tokens), by protocol and reason",
    ),
    row(
        METERING_PENDING_COALESCED_TOTAL,
        Counter,
        &[],
        None,
        "Metering cells coalesced into a per-bucket overflow sentinel because the write-behind accumulator was at its cap (sustained store outage); totals preserved, per-key attribution collapsed",
    ),
    row(
        CARD_ALARMS_TOTAL,
        Counter,
        &[],
        None,
        "Rate-card history alarms raised by the prices runtime",
    ),
    // Spend and budgets (scrape time).
    row(
        KEY_SPEND_CENTS,
        Gauge,
        &["key"],
        Some(Unit::Count),
        "Per-virtual-key accumulated spend in cents for the current budget window, plus the key's mint labels (scrape-time)",
    ),
    row(
        KEY_TOKENS_TOTAL,
        Gauge,
        &["key"],
        Some(Unit::Count),
        "Per-virtual-key accumulated tokens consumed in the current budget window, plus the key's mint labels (scrape-time)",
    ),
    row(
        BUCKET_TOKENS,
        Gauge,
        &["bucket", "model", "tier"],
        None,
        "Per-(bucket, model, tier) tokens in the bucket's current budget window (key buckets add the key's mint labels, budget-group buckets add group and window; derived from the token ledger at scrape time)",
    ),
    row(
        BUCKET_SPEND_CENTS,
        Gauge,
        &["bucket", "group", "window"],
        Some(Unit::Count),
        "Derived spend (abstract minor units) per budget-group bucket for its current window, recomputed from the token ledger x the current rate card at scrape time",
    ),
    row(
        BUCKET_BUDGET_REMAINING_CENTS,
        Gauge,
        &["bucket", "group", "window"],
        Some(Unit::Count),
        "Budget-group cap minus derived spend for the current window",
    ),
    // Lanes and pools (scrape time).
    row(
        LANE_STATE,
        Gauge,
        &["pool", "lane"],
        Some(Unit::Count),
        "Per-(pool,lane) circuit-breaker health: 0=healthy, 1=half-open, 2=tripped (scrape-time)",
    ),
    row(
        LANE_AVAILABLE,
        Gauge,
        &["pool", "lane"],
        Some(Unit::Count),
        "Per-(pool,lane) availability from the shared classify taxonomy: 1 = would admit, 0 = unavailable for any reason (breaker/capacity/dead/budget) (scrape-time)",
    ),
    row(
        LANE_RECOVERY_HINT_MS,
        Gauge,
        &["pool", "lane"],
        Some(Unit::Milliseconds),
        "Per-(pool,lane) honest lower bound (ms) on when an unavailable lane could next serve; 0 when available or no self-recovery basis (scrape-time)",
    ),
    row(
        LANE_INFLIGHT,
        Gauge,
        &["pool", "lane"],
        Some(Unit::Count),
        "Per-(pool,lane) in-flight requests (held concurrency permits) (scrape-time)",
    ),
    row(
        LANE_AVAILABLE_PERMITS,
        Gauge,
        &["pool", "lane"],
        Some(Unit::Count),
        "Per-(pool,lane) available concurrency permits for a BOUNDED lane (scrape-time; unbounded lanes emit no sample)",
    ),
    row(
        POOL_QUEUED,
        Gauge,
        &["pool"],
        Some(Unit::Count),
        "Per-pool requests currently parked in the on_exhausted queue bounded wait (scrape-time)",
    ),
    // Governance and durability.
    row(
        UNIT_CHECKPOINTS_TERMINAL,
        Gauge,
        &[],
        Some(Unit::Count),
        "Finished governed units whose spend awaits settlement in the store (the admission gate's terminal backlog, capped at 20,000) (scrape-time)",
    ),
    row(
        GOVERNED_ADMISSIONS_LIVE,
        Gauge,
        &[],
        Some(Unit::Count),
        "Governed admissions alive: released only after the unit's terminal checkpoint is staged (scrape-time)",
    ),
    row(
        STORE_SLOTS,
        Gauge,
        &["state"],
        None,
        "Store slot-queue entries by state (free, in_flight, in_doubt, resolved_uncollected, reconcile); the states add up to the pending operations",
    ),
    row(
        JOURNAL_QUARANTINED_TOTAL,
        Counter,
        &[],
        None,
        "Journal segments whose damaged remainder boot recovery moved into a quarantine file",
    ),
    row(
        AUDIT_STAGE_FAILURES_TOTAL,
        Counter,
        &[],
        None,
        "Terminal audit originals refused before native confirmation",
    ),
    // Export.
    row(
        EXPORT_DROPPED_TOTAL,
        Counter,
        &["instance", "reason"],
        None,
        "Terminally discarded export lines by instance and bounded reason",
    ),
    row(
        crate::export::delivery::EXPORT_CUSTODY_TOTAL,
        Counter,
        &["instance", "stream", "level"],
        None,
        "Accepted export lines by instance, stream and checked custody level",
    ),
    row(
        EXPORT_CAPTURE_REFUSALS_TOTAL,
        Counter,
        &["instance", "reason"],
        None,
        "Export capture admission refusals by instance and bounded reason",
    ),
    row(
        EXPORT_INTEGRITY_FAILURES_TOTAL,
        Counter,
        &["instance"],
        None,
        "Export audit integrity failure occurrences by instance",
    ),
    row(
        EXPORT_HELD_LINES,
        Gauge,
        &["instance", "reason"],
        None,
        "Current retained export ciphertext lines with an unavailable key by instance",
    ),
    carried(
        WEBHOOK_LOGS_DROPPED_TOTAL,
        &[],
        "Request-log webhook deliveries shed because the bounded delivery pool was saturated",
    ),
    carried(
        FILE_LOGS_DROPPED_TOTAL,
        &[],
        "Request-log file appends shed because the sink's bounded in-flight append pool was saturated",
    ),
    // Plugins and hooks.
    carried(
        TAP_NOTIFICATIONS_DROPPED_TOTAL,
        &[],
        "Fire-and-forget tap notifications dropped because the in-flight cap was reached",
    ),
    row(
        HOOK_PROJECT_OVER_CAP_TOTAL,
        Counter,
        &["part"],
        None,
        "Hooked-request projections the host refused because a plane asked for more room than the request can need, by part (arena, messages, signals)",
    ),
    row(
        PLUGIN_OBSERVATIONS_DROPPED_TOTAL,
        Counter,
        &[],
        None,
        "Plugin back-channels (reported metrics and diagnostics) dropped because the bounded observer intake was full",
    ),
    row(
        PLUGIN_TEXT_CUT_TOTAL,
        Counter,
        &["plugin", "field"],
        None,
        "Over-cap values received in plugin and hook replies, by plugin and field",
    ),
    row(
        PLUGIN_INSPECT_CAP_REFUSALS_TOTAL,
        Counter,
        &[],
        None,
        "Plugin inspections refused because the process opened its cap of distinct images for inspection",
    ),
    row(
        PLUGIN_INSPECT_SLOT_HELD_SECONDS,
        Gauge,
        &[],
        Some(Unit::Seconds),
        "How long the one plugin inspection slot has been held, in seconds (0 when free)",
    ),
    row(
        PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
        Counter,
        &[],
        None,
        "Plugin route requests whose forwarded headers were truncated to the plugin cap",
    ),
    row(
        PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL,
        Counter,
        &[],
        None,
        "Plugin route responses whose headers the host rejected",
    ),
    row(
        PLUGIN_LABEL_REFUSED_TOTAL,
        Counter,
        &[],
        None,
        "Plugin-reported metric labels the host refused",
    ),
    // Login.
    row(
        LOGIN_ATTEMPTS_TOTAL,
        Counter,
        &["method", "outcome"],
        None,
        "Credential submissions, by login method and outcome",
    ),
    row(
        LOGIN_THROTTLED_TOTAL,
        Counter,
        &["method", "limiter"],
        None,
        "Throttled credential submissions, by login method and limiter",
    ),
    // Build.
    row(
        BUILD_INFO,
        Gauge,
        &["version"],
        None,
        "Build identity: always 1, labelled with the running version",
    ),
];

/// The families a plane may carry on core's behalf, as the metric-family guard takes them: each
/// `plane_carried` row's name with exactly its label keys. Built once, off the request path.
#[must_use]
pub fn plane_carried_series() -> &'static [(&'static str, &'static [&'static str])] {
    static CARRIED: std::sync::LazyLock<Vec<(&'static str, &'static [&'static str])>> =
        std::sync::LazyLock::new(|| {
            HOST_METRICS
                .iter()
                .filter(|d| d.plane_carried)
                .map(|d| (d.name, d.labels))
                .collect()
        });
    &CARRIED
}

#[cfg(test)]
#[path = "../tests/metric_catalogue_tests.rs"]
mod tests;
