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
//!   Labels use ONLY configured pool names and lane MODEL strings (matching the proxy engine counter
//!   sites so gauge and counters PromQL-join on `lane`) — both bounded by operator config, never
//!   client-supplied values.
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
//! * `plane` — the governance plane the request arrived on (`crate::plane::Plane::key`): `llm`,
//!   `mcp` or `a2a`. Three values, and a fourth only if the codebase grows a fourth plane.
//! * Fixed enumerations (`outcome`, `disposition`, `reason`, `from`, `to`, `ingress_protocol`).
//!
//! Client-supplied values (raw model strings from request bodies, user-facing key secrets, etc.)
//! MUST NOT appear as metric labels. See the taxonomy constant block below for per-metric notes.

use std::sync::OnceLock;

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
// The scrape-time gauge NAMES: `describe()` registers them down in the substrate and
// `refresh_scrape_gauges`/`emit_lane_gauges` below emit them here, so this is a module-private
// `use` — core's own surface gains nothing, exactly as when they were private consts here.
use busbar_substrate::metrics::{
    BUCKET_BUDGET_REMAINING_CENTS, BUCKET_SPEND_CENTS, BUCKET_TOKENS, KEY_SPEND_CENTS,
    KEY_TOKENS_TOTAL, LANE_AVAILABLE, LANE_AVAILABLE_PERMITS, LANE_INFLIGHT, LANE_RECOVERY_HINT_MS,
    LANE_STATE, POOL_QUEUED,
};

// ─── PER-REQUEST HANDLE CACHE ─────────────────────────────────────────────────────────────────────
//
// `finish_inner` emits exactly two metrics on EVERY served request: the `REQUESTS_TOTAL` counter and
// the `REQUEST_DURATION_SECONDS` histogram. Emitting them through the `counter!`/`histogram!` macros
// re-runs, per request: three owned-`String` label allocations (`plane` + `ingress_protocol` + `pool`), a `Key`
// build, and a recorder registry hash+lookup — for a label set drawn from a FINITE, operator-bounded
// space (`|protocols| × (|pools| + 1) × |outcomes|`). `metrics::Counter`/`Histogram` are cheap-to-
// clone `Arc`-backed handles straight to the metric's storage that SURVIVE recorder swaps, so caching
// one per label set turns the steady-state hot path into a lock-free map read + an atomic increment —
// no per-request allocation and no registry lookup.
//
// The cache is a `RwLock<HashMap<Box<str>, Handle>>` keyed on a COMPACT single key built by joining
// the (bounded) label values with a `\x1f` unit separator — a byte that cannot appear in a protocol
// or pool name, so the join is unambiguous. Building that key is a single small allocation, but the
// steady-state path performs the lookup under a shared read lock and never touches the metrics
// registry (which would allocate the two `Label` Strings AND a `Key` AND hash+probe its own map);
// net, one small alloc replaces two label allocs + a `Key` build + a registry probe.
//
// Correctness vs. the recorder-install ordering the module contract calls out (a handle minted before
// `init()` installs the recorder binds to the no-op recorder FOREVER): the cache is populated ONLY
// once the recorder is installed (`HANDLE == Some(Some(_))`). Before that — `init()` not yet run, or
// install failed — these helpers fall through to the plain macro (itself a no-op against the default
// recorder), caching nothing. So a pre-`init()` emission is never cached, and every cached handle is
// bound to the real Prometheus recorder. In production `init()` runs at startup before any request
// reaches `finish_inner`, so the steady state is always the cached fast path.
use std::collections::HashMap;
use std::sync::RwLock;

/// Unit separator joining label values into the compact cache key — a control byte that cannot occur
/// in an ingress-protocol or pool name, so `"a\x1fb"` can never collide with `"a"` + `"\x1fb"`.
const CACHE_KEY_SEP: char = '\u{1f}';

static REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> = OnceLock::new();
static DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> = OnceLock::new();
// The mounted-plane (MCP/A2A) families keep their OWN caches: the `plane` label makes their key
// space distinct from the model series above, and keeping them separate is what lets the model
// series stay label-identical to v1.5.4.
static PLANE_REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> =
    OnceLock::new();
static PLANE_DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> =
    OnceLock::new();

/// Increment `REQUESTS_TOTAL` for `(ingress_protocol, pool, outcome)` via a CACHED counter handle —
/// no registry lookup and no per-request `Label`/`Key` construction on the steady-state path. Falls
/// back to the plain macro until the recorder is installed (see the cache-module note above).
/// Byte-for-byte the same series and value the macro produced. This is the MODEL plane's family and
/// carries NO `plane` label, so its exposition is identical to v1.5.4 (`incr_plane_requests_total`
/// is the mounted-plane counterpart).
pub(crate) fn incr_requests_total(ingress_protocol: &str, pool: &str, outcome: &'static str) {
    // This `!recorder_installed()` branch is real (it exists so pre-install traffic never caches a
    // handle bound to the no-op recorder), but it is NOT practically unit-testable in this crate
    // as it stands. `ENABLED`/`HANDLE` are process-global `OnceLock`s that install (via `init()`)
    // exactly once per process and never uninstall; `busbar`'s crate is `[[bin]]`-only (no `[lib]`
    // target — see Cargo.toml), so there is no way for a `tests/*.rs` integration test to link the
    // crate's internals into its OWN separate process either (the only integration-test pattern
    // available, `tests/cli_validate.rs`, black-box-spawns the built binary as a subprocess
    // instead). Within the single shared `#[cfg(test)]` unit-test process, some other test has
    // near-certainly already called `init()` before this one runs (parallel test execution, no
    // ordering guarantee), so this branch is unreachable from a normal `#[test]`. A real fix would
    // mean adding a `[lib]` target to this crate purely to enable a never-calls-init() integration
    // test binary, which is out of scope here. Externally, the two branches are ALSO behaviorally
    // identical before install: both ultimately call the same no-op `metrics::counter!` macro
    // against the default recorder, so even a real subprocess test could not distinguish them by
    // observable effect. Left as a documented, investigated limitation.
    if !recorder_installed() {
        // Pre-install: don't cache (would bind to the no-op recorder). The macro is itself a no-op.
        metrics::counter!(
            REQUESTS_TOTAL,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string(),
            "outcome" => outcome
        )
        .increment(1);
        return;
    }
    let cache = REQUESTS_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}{CACHE_KEY_SEP}{outcome}");
    // Fast path: shared-read hit (the common case — a bounded, quickly-saturated key set).
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.increment(1);
        return;
    }
    // Cold path (first time this label set is seen): register the handle once, then cache it.
    let handle = metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    );
    handle.increment(1);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

/// Increment `PLANE_REQUESTS_TOTAL` for `(plane, ingress_protocol, pool, outcome)` — the mounted-plane
/// (MCP/A2A) counterpart of [`incr_requests_total`]. SEPARATE family and SEPARATE cache so the model
/// series stays label-identical to v1.5.4; same cached-handle contract otherwise.
pub(crate) fn incr_plane_requests_total(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
) {
    if !recorder_installed() {
        metrics::counter!(
            PLANE_REQUESTS_TOTAL,
            "plane" => plane.to_string(),
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string(),
            "outcome" => outcome
        )
        .increment(1);
        return;
    }
    let cache = PLANE_REQUESTS_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!(
        "{plane}{CACHE_KEY_SEP}{ingress_protocol}{CACHE_KEY_SEP}{pool}{CACHE_KEY_SEP}{outcome}"
    );
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.increment(1);
        return;
    }
    let handle = metrics::counter!(
        PLANE_REQUESTS_TOTAL,
        "plane" => plane.to_string(),
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    );
    handle.increment(1);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

/// Record a `REQUEST_DURATION_SECONDS` observation for `(ingress_protocol, pool)` via a CACHED
/// histogram handle. Same caching contract as [`incr_requests_total`]; the model plane's family,
/// with NO `plane` label (see [`record_plane_request_duration`] for the mounted-plane counterpart).
pub(crate) fn record_request_duration(ingress_protocol: &str, pool: &str, seconds: f64) {
    if !recorder_installed() {
        metrics::histogram!(
            REQUEST_DURATION_SECONDS,
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string()
        )
        .record(seconds);
        return;
    }
    let cache = DURATION_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{ingress_protocol}{CACHE_KEY_SEP}{pool}");
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.record(seconds);
        return;
    }
    let handle = metrics::histogram!(
        REQUEST_DURATION_SECONDS,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    );
    handle.record(seconds);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

/// Record a `PLANE_REQUEST_DURATION_SECONDS` observation for `(plane, ingress_protocol, pool)` — the
/// mounted-plane (MCP/A2A) counterpart of [`record_request_duration`], in a SEPARATE family/cache.
pub(crate) fn record_plane_request_duration(
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    seconds: f64,
) {
    if !recorder_installed() {
        metrics::histogram!(
            PLANE_REQUEST_DURATION_SECONDS,
            "plane" => plane.to_string(),
            "ingress_protocol" => ingress_protocol.to_string(),
            "pool" => pool.to_string()
        )
        .record(seconds);
        return;
    }
    let cache = PLANE_DURATION_HANDLES.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{plane}{CACHE_KEY_SEP}{ingress_protocol}{CACHE_KEY_SEP}{pool}");
    if let Some(h) = cache
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(key.as_str())
    {
        h.record(seconds);
        return;
    }
    let handle = metrics::histogram!(
        PLANE_REQUEST_DURATION_SECONDS,
        "plane" => plane.to_string(),
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    );
    handle.record(seconds);
    cache
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(key.into_boxed_str())
        .or_insert(handle);
}

/// Refresh all scrape-time gauges from in-process reads. Called on every `/metrics` scrape so
/// values are current at observation time. The reads are all side-effect-free:
/// * Governance: `GovState::usage_for` queries the SQLite store (offloaded to the blocking pool
///   by the caller when in async context, or inline in unit tests).
/// * Lane health: `store.snapshot()` + `store.cooldown_remaining_in()` — pure atomic reads that
///   do NOT trigger Open→HalfOpen transitions or acquire the single-flight recovery probe.
///
/// No-op when governance is disabled (the governance arc is `None`). Pool and lane label spaces
/// are bounded by the operator's configuration; virtual-key ids are bounded by the set of
/// keys the admin has created. No client-supplied label values are ever emitted.
pub fn refresh_scrape_gauges(app: &App) {
    let now = crate::state::now();

    // ── Governance: per-key spend, budget-remaining, tokens ────────────────────────────────────
    if let Some(gov) = &app.governance {
        // `all_keys()` lists every VirtualKey from the SQLite store; this is a low-frequency scrape
        // path. On error we skip only the PER-KEY gauge refresh below (by treating the key list as
        // empty) rather than returning a stale/wrong per-key value. This must NOT `return` out of
        // the whole function: the group-bucket loop just below does not consume `keys` at all (it
        // walks `app.cost.groups()` and has its own per-bucket error handling), and the lane-health
        // gauges further down don't touch governance at all — an unrelated governance-store hiccup
        // must not blind Prometheus to a breaker tripping during that exact window (see
        // GAUGE_IDLE_TIMEOUT: a skipped refresh leaves the last-known value looking "current" for up
        // to 24h).
        let keys = match gov.all_keys() {
            Ok(ks) => ks,
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_LIST_KEYS_FAILED, error = %e, "metrics scrape: failed to list virtual keys; skipping per-key spend/token gauges");
                Vec::new()
            }
        };
        // Cap per-key gauge emission. Above this many keys, emitting one series per key per scrape
        // (×3 gauges) would blow up Prometheus cardinality AND walk the store once per key on every
        // scrape. Bound BOTH by emitting at most `key_gauge_limit` keys; warn when truncating so the
        // condition is visible. Generous default — normal deployments never reach it. (A configurable
        // limit / top-N-by-spend selection is a v1.x refinement.)
        // Operator-tunable via `metrics.key_gauge_limit` (default 2000).
        let key_gauge_limit = crate::limits::key_gauge_limit();
        // Warn-once latch: the key count exceeding the gauge limit is an actionable but STABLE
        // condition (it persists across every scrape until the operator tunes
        // `metrics.key_gauge_limit` or the key count drops), and this scrape runs on every /metrics
        // pull. Warn on the TRANSITION into the over-limit state; hold subsequent scrapes at debug so
        // a busy scrape cadence cannot spam. Cleared when the count falls back under the limit so a
        // future breach re-warns.
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
        for key in keys.iter().take(key_gauge_limit) {
            // `usage_for` queries the SQLite store for the key's current-window counters.
            let usage = match gov.usage_for(&app.cost, &key.id, now) {
                Ok(Some(u)) => u,
                Ok(None) => continue, // key vanished between list and get — skip
                Err(e) => {
                    diag_debug!(METRICS_SCRAPE_KEY_USAGE_READ_FAILED, key = %key.id, error = %e, "metrics scrape: usage read failed; skipping key");
                    continue;
                }
            };
            // key label = the operator-visible virtual-key id (`vk_<hex>`), never the bearer
            // secret. The key's MINT-TIME labels (e.g. team=growth) are echoed onto every series
            // so external Grafana can `sum by (team)` and Alertmanager can fire per team WITHOUT
            // busbar knowing what "team" means. Label KEYS are operator-chosen at mint (bounded by
            // the admin surface), never request bytes.
            let base_labels = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                let mut labels: Vec<metrics::Label> =
                    vec![metrics::Label::new("key", key.id.clone())];
                for (k, v) in &key.labels {
                    labels.push(metrics::Label::new(k.clone(), v.clone()));
                }
                for (k, v) in extra {
                    labels.push(metrics::Label::new(*k, v.clone()));
                }
                labels
            };
            metrics::gauge!(KEY_SPEND_CENTS, base_labels(&[])).set(usage.spend_cents as f64);
            metrics::gauge!(KEY_TOKENS_TOTAL, base_labels(&[])).set(usage.tokens as f64);
            // 1.5.0: keys are PURE AUTH (no inline budget cap), so there is no per-key
            // budget-remaining gauge; remaining/limit headroom lives on the GROUP buckets below.
            // Per-(bucket, model, tier) token gauges from the key bucket's ledger (the raw
            // material any external per-model cost dashboard multiplies by its own catalog). The
            // key's attribution bucket accrues in the all-time window.
            for (model, tokens) in
                gov.bucket_model_tokens(&key.id, crate::governance::WINDOW_TOTAL, now)
            {
                let tier_v = |u: &str| tokens.get(u).copied().unwrap_or(0);
                for (tier, v) in [
                    ("input", tier_v(busbar_api::UNIT_INPUT)),
                    ("output", tier_v(busbar_api::UNIT_OUTPUT)),
                    ("cache_read", tier_v(busbar_api::UNIT_CACHE_READ)),
                    ("cache_write", tier_v(busbar_api::UNIT_CACHE_WRITE)),
                ] {
                    let mut labels: Vec<metrics::Label> =
                        vec![metrics::Label::new("bucket", key.id.clone())];
                    for (k, val) in &key.labels {
                        labels.push(metrics::Label::new(k.clone(), val.clone()));
                    }
                    labels.push(metrics::Label::new("model", model.clone()));
                    labels.push(metrics::Label::new("tier", tier));
                    metrics::gauge!(BUCKET_TOKENS, labels).set(v as f64);
                }
            }
        }

        // ── GROUP buckets: derived spend + remaining + per-(model, tier) tokens, one series per
        // (group, window) enforcement bucket. Bounded by |groups| x |windows-in-use| (operator-
        // owned names + the fixed window vocabulary). Spend derives fresh from the ledger x the
        // CURRENT rate card (reprice-on-read), fee included (each bucket counts its own requests).
        // The `group` and `window` labels are the 1.5.0 limit dimensions; `bucket` stays the raw
        // ledger id for join-ability with the store.
        for group in app.cost.groups() {
            for bucket in &group.buckets {
                let derived = match gov.derived_bucket_usage(
                    &app.cost,
                    &bucket.bucket_id,
                    bucket.window,
                    true,
                    now,
                ) {
                    Ok(u) => u,
                    Err(e) => {
                        diag_debug!(METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, bucket = %bucket.bucket_id, error = %e, "metrics scrape: group ledger read failed; skipping");
                        continue;
                    }
                };
                let dims = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                    let mut labels = vec![
                        metrics::Label::new("bucket", bucket.bucket_id.clone()),
                        metrics::Label::new("group", group.name.clone()),
                        metrics::Label::new("window", bucket.window),
                    ];
                    for (k, v) in extra {
                        labels.push(metrics::Label::new(*k, v.clone()));
                    }
                    labels
                };
                metrics::gauge!(BUCKET_SPEND_CENTS, dims(&[])).set(derived.spend_cents as f64);
                // Budget-remaining: only for a bucket that carries a `budget` cap.
                if let Some(cap) = bucket.budget_cap {
                    let remaining = cap.saturating_sub(derived.spend_cents).max(0);
                    metrics::gauge!(BUCKET_BUDGET_REMAINING_CENTS, dims(&[])).set(remaining as f64);
                }
                for (model, tokens) in
                    gov.bucket_model_tokens(&bucket.bucket_id, bucket.window, now)
                {
                    let tier_v = |u: &str| tokens.get(u).copied().unwrap_or(0);
                    for (tier, v) in [
                        ("input", tier_v(busbar_api::UNIT_INPUT)),
                        ("output", tier_v(busbar_api::UNIT_OUTPUT)),
                        ("cache_read", tier_v(busbar_api::UNIT_CACHE_READ)),
                        ("cache_write", tier_v(busbar_api::UNIT_CACHE_WRITE)),
                    ] {
                        metrics::gauge!(
                            BUCKET_TOKENS,
                            dims(&[("model", model.clone()), ("tier", tier.to_string())])
                        )
                        .set(v as f64);
                    }
                }
            }
        }
    }

    // ── Lane health: per-(pool, lane-index) breaker state ──────────────────────────────────────
    // For each configured pool, iterate the pool's lane members. The lane state is derived from
    // the lane snapshot (dead flag, aggregate usability, aggregate cooldown remaining), which are
    // pure atomic reads — no FSM transitions are triggered. The `lane` label value is the lane's
    // MODEL string (matching the proxy engine counters; bounded one-per-configured-lane, a startup
    // constant), not a numeric index.
    //
    // State derivation (3-state: 0=healthy, 1=half-open, 2=tripped):
    //   dead || (!usable && cooldown > 0) → 2 (hard-down or all cells Open)
    //   usable && cooldown > 0            → 1 (some cells admit but aggregate cooling down)
    //   usable && cooldown == 0           → 0 (healthy / all cells Closed)
    //
    // `snapshot()` is LANE-GLOBAL (indexed by lane, not scoped to a pool) and `now` is fixed for the
    // whole scrape, so a lane shared across K pools would otherwise recompute the identical (now-2x)
    // breaker-cell fold K times. Memoize it per lane_idx here and reuse across every pool that shares
    // the lane (and across the by_model loop below). Per-POOL facts (`classify(pool, …)`,
    // `cooldown_remaining_in(pool, …)`) stay per-iteration — only the lane-global snapshot is cached.
    let mut snap_cache: std::collections::HashMap<usize, crate::store::LaneSnapshot> =
        std::collections::HashMap::new();
    // The routing tables through the NEUTRAL read seam (money-path Phase 3-4 B): the scrape reads pool
    // label spaces, per-pool member lane indices, a lane's model string, and the per-pool queue depth
    // as neutral projections, so `/metrics` names no `Lane`/`WeightedLane` and need not relocate when
    // the tables move into `busbar-llm`. Cold scrape path — the projections may allocate.
    let view = app.engine_tables_view();
    for (pool_name, member_idxs) in view.pools() {
        // Render the LIVE per-pool `on_exhausted: queue` park depth. `queued_depth` is the
        // RAII-maintained source incremented while a request waits on a candidate lane's semaphore
        // (see `walk.rs` `handle_queue` + `state::QueuedDepth`); a pool that never queues reads 0.
        metrics::gauge!(POOL_QUEUED, "pool" => pool_name.to_string())
            .set(view.queued_depth(pool_name) as f64);
        for lane_idx in member_idxs {
            let snap = snap_cache
                .entry(lane_idx)
                .or_insert_with(|| app.store.snapshot(lane_idx, now));
            // Per-pool cooldown check: use `cooldown_remaining_in` for this specific (pool, lane)
            // cell, not the lane-wide aggregate from the snapshot (which may reflect a different
            // pool's cell). This gives per-pool accuracy without touching the FSM.
            let pool_cooldown = app.store.cooldown_remaining_in(pool_name, lane_idx, now);
            let state_val: f64 = if snap.dead || (pool_cooldown > 0 && !snap.usable) {
                2.0 // hard-down or all cells Open/tripped
            } else if pool_cooldown > 0 {
                1.0 // HalfOpen: this cell has a non-zero cooldown but the lane still admits
            } else {
                0.0 // Closed / healthy
            };
            // The `lane` label is the lane's MODEL string (NOT a numeric index), matching the
            // counter sites in proxy engine so the gauge and counters can be PromQL-joined on `lane`.
            // It is bounded one-per-configured-lane (a startup constant), so cardinality stays safe.
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
            // Render the lane's availability from the SAME per-(pool, lane) `classify`
            // routing dispatches on — this IS the pool cell the pool routes through.
            let avail = app.store.classify(pool_name, lane_idx, now);
            emit_lane_gauges(pool_name, &lane_label, snap, &avail, now);
        }
    }

    // Direct-model lanes (reachable via `by_model` routing, no pool required) get a lane-state
    // gauge too, labeled with the model name as `pool` — the same convention the counters use
    // for model-routed traffic (`proxy::metric_pool_label`: empty pool name → model string),
    // so gauge and counters PromQL-join. Cardinality: bounded by |configured models|, a startup
    // constant. Without this, a pool-less config (the docs' minimal getting-started config)
    // exposes NO lane gauges at all — a fresh boot rendered an empty /metrics (harness finding,
    // 2026-07-09). The breaker cell is the lane-default `""` cell, matching model-routed
    // fault attribution.
    for (model, lane_idx) in view.model_indices() {
        // Reuse the lane-global snapshot cached in the pool loop above (or compute+cache on miss for a
        // pool-less lane) — same lane_idx, same fixed `now`.
        let snap = snap_cache
            .entry(lane_idx)
            .or_insert_with(|| app.store.snapshot(lane_idx, now));
        let cooldown = app.store.cooldown_remaining_in("", lane_idx, now);
        let state_val: f64 = if snap.dead || (cooldown > 0 && !snap.usable) {
            2.0
        } else if cooldown > 0 {
            1.0
        } else {
            0.0
        };
        let lane_model = view
            .lane_view(lane_idx)
            .expect("model-routed lane index is in range")
            .model
            .to_string();
        metrics::gauge!(
            LANE_STATE,
            "pool" => model.to_string(),
            "lane" => lane_model.clone()
        )
        .set(state_val);
        // Direct-model lane: classify against the lane-default (`""`) cell, matching model-routed
        // fault attribution (the same cell `LANE_STATE` reads via `cooldown_remaining_in("", ...)`).
        let avail = app.store.classify("", lane_idx, now);
        emit_lane_gauges(model, &lane_model, snap, &avail, now);
    }
}

/// Emit the per-(pool, lane) availability + depth gauges. `avail` is the SAME
/// `classify(pool, lane, now)` verdict routing dispatches on, so `busbar_lane_available` (1=Ok/0=Err)
/// and `busbar_lane_recovery_hint_ms` (from `Unavailable::recovery_hint_ms`, 0 when available or no
/// self-recovery basis) can never drift from behaviour. `busbar_lane_inflight` is always emitted;
/// `busbar_lane_available_permits` only for BOUNDED lanes (an unbounded lane has no meaningful permit
/// count, so it emits no sample rather than a misleading infinite one). The breaker (`LANE_STATE`) and
/// capacity (`available_permits`) axes stay INDEPENDENT of the collapsed `LANE_AVAILABLE` bool.
/// Shared by the pool loop and the by_model loop so the two label conventions (`pool`=pool name /
/// `pool`=model name) stay identical to `LANE_STATE`.
fn emit_lane_gauges(
    pool_label: &str,
    lane_label: &str,
    snap: &crate::store::LaneSnapshot,
    avail: &Result<(), crate::store::Unavailable>,
    now: u64,
) {
    // Build the `pool`/`lane` labels ONCE per lane (the two `to_string()` allocations) and clone the
    // pair per gauge, instead of re-allocating both Strings on each of the 3-4 gauge emits (was a
    // closure called every time). The two label values are identical across every gauge here.
    let pool_l = metrics::Label::new("pool", pool_label.to_string());
    let lane_l = metrics::Label::new("lane", lane_label.to_string());
    metrics::gauge!(LANE_AVAILABLE, vec![pool_l.clone(), lane_l.clone()]).set(if avail.is_ok() {
        1.0
    } else {
        0.0
    });
    // Honest recovery hint: 0 when available (Ok) or the reason has no self-recovery basis (None).
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

// `GET /metrics` (the Prometheus text exposition) is no longer served by a core route here: 1.5.3
// lifted the DISTRIBUTION half out to the built-in `prometheus` EXPORTER
// ([`crate::export::prometheus`]), which serves it via the plugin HTTP endpoint registration
// (`handle_http`) and renders the SAME registry through [`render`] after refreshing the scrape-time
// gauges via [`refresh_scrape_gauges`]. COLLECTION (this recorder + the emit sites + the gauge
// derivation) stays core.

#[cfg(test)]
#[path = "tests/metrics_tests.rs"]
mod tests;
