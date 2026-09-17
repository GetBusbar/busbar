// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Prometheus metrics: a process-wide recorder + the `/metrics` exposition.
//!
//! `init()` installs a single global `metrics-exporter-prometheus` recorder. Emission sites
//! across the codebase use the `metrics` facade macros (`counter!`/`histogram!`/`gauge!`), which
//! route to that recorder. `render()` produces the current Prometheus text exposition, served by
//! `handler()` on `GET /metrics`.
//!
//! ## Scrape-time gauges
//!
//! Four families of gauges are REFRESHED AT SCRAPE TIME (in `handler()`) from already-available
//! in-process reads. They are NOT emitted on the request hot path:
//!
//! * **`busbar_key_spend_cents`** — per-virtual-key accumulated spend in the current budget window
//!   (cents). Only populated when governance is enabled.
//! * **`busbar_key_budget_remaining_cents`** — max_budget_cents minus spend for keys that carry a
//!   budget cap. Enables Prometheus burn-rate alerts on a bounded, operator-configured label space.
//! * **`busbar_key_tokens_total`** — accumulated tokens consumed by each virtual key in the current
//!   budget window. Useful for token-cost dashboards.
//! * **`busbar_lane_state`** — per-(pool, lane) health gauge: 0 = healthy/closed, 1 =
//!   half-open (cooling but at least one cell admits), 2 = tripped (all cells Open or hard-down).
//!   Labels use ONLY configured pool names and lane MODEL strings (matching the request-counter
//!   emission sites below so gauge and counters PromQL-join on `lane`) — both bounded by operator
//!   config, never client-supplied values.
//!
//! ## Cardinality invariant
//!
//! Every label on every metric in this module is drawn from a FINITE, OPERATOR-CONTROLLED set:
//! * `pool` — the name of a configured pool (`app.pools` key-set), or the sentinel `"unresolved"`.
//! * `key` — the virtual-key id (a hex prefix of the key's secret hash, operator-issued, bounded
//!   by the count of created keys — never the raw bearer token).
//! * `lane` — the lane's configured MODEL string (bounded by the count of configured lanes, a
//!   startup constant). Identical on the LANE_STATE gauge and every counter that carries `lane`, so
//!   they can be PromQL-joined on the label.
//! * `plane` — the key of the plane the request arrived on (the primary/fallback plane's own key,
//!   or a mounted plane consumer's registered key). Bounded by the small, fixed set of plane
//!   consumers a build can mount.
//! * Fixed enumerations (`outcome`, `disposition`, `reason`, `from`, `to`, `ingress_protocol`).
//!
//! Client-supplied values (raw model strings from request bodies, user-facing key secrets, etc.)
//! MUST NOT appear as metric labels. See the taxonomy constant block below for per-metric notes.

use crate::diagnostics::{
    diag_debug, diag_warn, METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
    METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, METRICS_SCRAPE_KEY_USAGE_READ_FAILED,
    METRICS_SCRAPE_LIST_KEYS_FAILED,
};
use crate::state::App;

// ── THE RECORDER INSTALL, RE-EXPORTED BY IDENTITY FROM THE NEUTRAL SUBSTRATE ─────────────────────
//
// The opt-in flag, the install, the maintenance drain, the HELP/TYPE registrations, `render()` and
// every metric NAME moved DOWN to `busbar_substrate::metrics` (all `App`-free; see there). These are
// the SAME items at their historical `crate::metrics::…` paths — one registry, one exposition — so
// every core call site below and elsewhere resolves unchanged. The `App`-shaped half
// (`refresh_scrape_gauges`, `emit_lane_gauges`, the per-request handle caches) stays here.
pub use busbar_substrate::metrics::{
    configure, render, PLANE_REQUESTS_TOTAL, PLANE_REQUEST_DURATION_SECONDS, REQUESTS_TOTAL,
    REQUEST_DURATION_SECONDS,
};
// The test-only arg-less initializer carries its historical gate: there is still deliberately no
// arg-less installer outside tests, so no shipped build path can install metrics without a named
// retention window.
#[cfg(any(test, feature = "test-support"))]
pub use busbar_substrate::metrics::init;
// The builder seam and the shipped gauge idle window the reaping battery below drives. Test-only on
// both sides of the seam, so core's shipped surface gains nothing.
#[cfg(test)]
pub(crate) use busbar_substrate::metrics::recorder_internals::{
    recorder_builder, GAUGE_IDLE_TIMEOUT,
};
pub(crate) use busbar_substrate::metrics::{
    enabled, recorder_installed, ADMISSION_DENIED_TOTAL, BREAKER_TRIPS_TOTAL, FAILOVERS_TOTAL,
    FILE_LOGS_DROPPED_TOTAL, FILE_LOGS_ROTATED_TOTAL, FILE_LOGS_ROTATE_FAILED_TOTAL,
    METERING_PENDING_COALESCED_TOTAL, PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
    PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL, PROMETHEUS_CONTENT_TYPE, TRANSLATIONS_TOTAL,
    WEBHOOK_LOGS_DROPPED_TOTAL,
};
pub use busbar_substrate::metrics::{
    BILLING_TRUNCATED_TOTAL, HOOK_CONTENT_TRUNCATED_TOTAL, ROUTE_POLICY_REJECTIONS_TOTAL,
    ROUTE_POLICY_SELECTIONS_TOTAL, UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL,
};
// The maintenance drain and the retention decision are driven from PRODUCTION down in the substrate
// (the maintenance thread and `HistogramSlot::record`); core names them only from the batteries that
// pin the drain-on-a-timer and the three-state retention truth table, so the re-export is test-only.
#[cfg(test)]
pub(crate) use busbar_substrate::metrics::{drain_pending, retaining, retaining_from};
// The per-request cached-handle emit helpers moved DOWN to the neutral substrate alongside the
// recorder install they feed (they name only the substrate metric consts, `recorder_installed`, and
// the `metrics` macros — no `App`). Re-exported here so the `&App` telemetry wrappers in
// `crate::telemetry` (their only callers) resolve `crate::metrics::…` unchanged and emit byte-identical
// series.
pub(crate) use busbar_substrate::metrics::{
    incr_plane_requests_total, incr_requests_total, record_plane_request_duration,
    record_request_duration,
};
// The scrape-time gauge NAMES + the gauge COMPOSITION/emit + `emit_lane_gauges` moved DOWN to the
// substrate behind the neutral `ScrapeSource` seam (`busbar_substrate::metrics::refresh_scrape_gauges`);
// core keeps only the thin `impl ScrapeSource for App` (App field reads) + the call-site wrapper below,
// so it no longer names the gauge consts directly.
use busbar_substrate::metrics::{KeyUsage, ScrapeGroupBucket, ScrapeKey, ScrapeSource, TierTokens};
// The scrape-time gauge NAME consts are now emitted only down in the substrate, so core's shipped
// code no longer references them — but this module's own tests (`tests/metrics_tests.rs`, which pulls
// `use super::*`) assert against the rendered exposition by these names. Keep them in scope for the
// test build only, so the shipped surface gains nothing while the byte-shape batteries still resolve.
#[cfg(test)]
use busbar_substrate::metrics::{
    BUCKET_BUDGET_REMAINING_CENTS, BUCKET_SPEND_CENTS, BUCKET_TOKENS, KEY_SPEND_CENTS,
    KEY_TOKENS_TOTAL, LANE_AVAILABLE, LANE_AVAILABLE_PERMITS, LANE_INFLIGHT, LANE_RECOVERY_HINT_MS,
    LANE_STATE, POOL_QUEUED,
};

// The per-request cached-handle emit helpers (`incr_requests_total` / `incr_plane_requests_total` /
// `record_request_duration` / `record_plane_request_duration`) moved DOWN to the neutral substrate
// alongside the recorder install they feed (they name only the substrate metric consts,
// `recorder_installed`, and the `metrics` macros — no `App`). Their only callers — the `&App` request
// emit wrappers — ALSO moved down behind the `TelemetrySource` seam and now name
// `busbar_substrate::metrics::…` directly, so core no longer references them.

/// Refresh all scrape-time gauges from in-process reads. Called on every `/metrics` scrape so values
/// are current at observation time. A THIN call site over the neutral
/// [`busbar_substrate::metrics::refresh_scrape_gauges`] composition — every `App` field read (and its
/// fallible governance/store projection) lives in the [`ScrapeSource`] impl below. The reads are all
/// side-effect-free (governance queries the SQLite store; lane health is pure atomic reads that do NOT
/// trigger Open→HalfOpen transitions). No-op for the governance families when governance is disabled.
pub fn refresh_scrape_gauges(app: &App) {
    busbar_substrate::metrics::refresh_scrape_gauges(app)
}

/// THE THIN `App`-reading half of the scrape seam. Every method is an `App` field read plus the
/// fallible governance/store projection it always was; the substrate NAMES this trait and performs ALL
/// gauge composition/emission (see [`busbar_substrate::metrics::refresh_scrape_gauges`]). The
/// scrape-path diagnostics and the per-key gauge-limit cap stay here because their diagnostic constants
/// and warn-once latch live in core.
impl ScrapeSource for App {
    fn governance_enabled(&self) -> bool {
        self.governance.is_some()
    }

    fn scrape_keys(&self) -> Vec<ScrapeKey> {
        let Some(gov) = &self.governance else {
            return Vec::new();
        };
        // `all_keys()` lists every VirtualKey from the SQLite store. On error skip only the per-key
        // gauges (empty list) rather than returning a stale/wrong value — an unrelated governance-store
        // hiccup must not blind Prometheus to a breaker tripping during that exact window.
        let keys = match gov.all_keys() {
            Ok(ks) => ks,
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_LIST_KEYS_FAILED, error = %e, "metrics scrape: failed to list virtual keys; skipping per-key spend/token gauges");
                return Vec::new();
            }
        };
        // Cap per-key gauge emission (bounds Prometheus cardinality AND scrape-path DB load).
        // Operator-tunable via `metrics.key_gauge_limit` (default 2000). Warn-once latch: warn on the
        // TRANSITION into the over-limit state; hold subsequent scrapes at debug so a busy scrape
        // cadence cannot spam; cleared when the count falls back under the limit so a future breach
        // re-warns.
        let key_gauge_limit = crate::limits::key_gauge_limit();
        static KEY_GAUGE_LIMIT_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if keys.len() > key_gauge_limit {
            if !KEY_GAUGE_LIMIT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_warn!(
                    METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
                    key_count = keys.len(),
                    limit = key_gauge_limit,
                    "metrics scrape: virtual-key count exceeds per-key gauge limit; emitting gauges \
                     for only the first `limit` keys to bound cardinality and scrape-path DB load",
                );
            } else {
                diag_debug!(
                    METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
                    key_count = keys.len(),
                    limit = key_gauge_limit,
                    "metrics scrape: virtual-key count still exceeds per-key gauge limit; emitting \
                     gauges for only the first `limit` keys to bound cardinality and scrape-path DB \
                     load",
                );
            }
        } else {
            KEY_GAUGE_LIMIT_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        keys.into_iter()
            .take(key_gauge_limit)
            .map(|key| ScrapeKey {
                id: key.id.clone(),
                labels: key
                    .labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            })
            .collect()
    }

    fn key_usage(&self, id: &str, now: u64) -> Option<KeyUsage> {
        let gov = self.governance.as_ref()?;
        // `usage_for` queries the SQLite store for the key's current-window counters.
        match gov.usage_for(&self.cost, id, now) {
            Ok(Some(u)) => Some(KeyUsage {
                spend_cents: u.spend_cents,
                tokens: u.tokens,
            }),
            Ok(None) => None, // key vanished between list and get — skip
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_KEY_USAGE_READ_FAILED, key = %id, error = %e, "metrics scrape: usage read failed; skipping key");
                None
            }
        }
    }

    fn key_model_tokens(&self, id: &str, now: u64) -> Vec<(String, TierTokens)> {
        let Some(gov) = &self.governance else {
            return Vec::new();
        };
        // The key's attribution bucket accrues in the all-time window.
        gov.bucket_model_tokens(id, crate::governance::WINDOW_TOTAL, now)
            .into_iter()
            .map(|(model, tokens)| (model, tier_tokens(&tokens)))
            .collect()
    }

    fn scrape_group_buckets(&self) -> Vec<ScrapeGroupBucket> {
        let mut out = Vec::new();
        for group in self.cost.groups() {
            for bucket in &group.buckets {
                out.push(ScrapeGroupBucket {
                    bucket_id: bucket.bucket_id.clone(),
                    group_name: group.name.clone(),
                    window: bucket.window,
                    budget_cap: bucket.budget_cap,
                });
            }
        }
        out
    }

    fn group_bucket_spend(&self, bucket_id: &str, window: &str, now: u64) -> Option<i64> {
        let gov = self.governance.as_ref()?;
        // Spend derives fresh from the ledger x the CURRENT rate card (reprice-on-read), fee included
        // (`true`) so it matches what the enforcer sees.
        match gov.derived_bucket_usage(&self.cost, bucket_id, window, true, now) {
            Ok(u) => Some(u.spend_cents),
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, bucket = %bucket_id, error = %e, "metrics scrape: group ledger read failed; skipping");
                None
            }
        }
    }

    fn group_model_tokens(
        &self,
        bucket_id: &str,
        window: &str,
        now: u64,
    ) -> Vec<(String, TierTokens)> {
        let Some(gov) = &self.governance else {
            return Vec::new();
        };
        gov.bucket_model_tokens(bucket_id, window, now)
            .into_iter()
            .map(|(model, tokens)| (model, tier_tokens(&tokens)))
            .collect()
    }

    fn lane_runtime(&self) -> &dyn busbar_substrate::store::LaneRuntime {
        &*self.store
    }

    fn engine_view(&self) -> &dyn busbar_substrate::plane_host::EngineTablesView {
        self.engine_tables_view()
    }
}

/// Project one bucket's per-(model) token `BTreeMap` into the neutral [`TierTokens`], reading the four
/// fixed pricing tiers by their `busbar_api::UNIT_*` keys (0 when a tier is absent). Keeps the substrate
/// free of the `busbar_api::UNIT_*` names while preserving the exact per-tier values and order.
fn tier_tokens(tokens: &std::collections::BTreeMap<String, u64>) -> TierTokens {
    let v = |u: &str| tokens.get(u).copied().unwrap_or(0);
    TierTokens {
        input: v(busbar_api::UNIT_INPUT),
        output: v(busbar_api::UNIT_OUTPUT),
        cache_read: v(busbar_api::UNIT_CACHE_READ),
        cache_write: v(busbar_api::UNIT_CACHE_WRITE),
    }
}

// `GET /metrics` (the Prometheus text exposition) is no longer served by a core route here: 1.5.3
// lifted the DISTRIBUTION half out to the built-in `prometheus` EXPORTER
// ([`crate::export::prometheus`]), which serves it via the plugin HTTP endpoint registration
// (`handle_http`) and renders the SAME registry through [`render`] after refreshing the scrape-time
// gauges via [`refresh_scrape_gauges`]. COLLECTION (this recorder + the emit sites + the gauge
// derivation) stays core.

#[cfg(test)]
#[path = "tests/metrics_tests.rs"]
mod tests;
