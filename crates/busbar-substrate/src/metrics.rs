// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL METRIC-NAME FACADE, in the substrate.
//!
//! These are the Prometheus metric NAMES a plane's engine emits into the process-global recorder via
//! the `metrics` facade macros (`counter!`/`histogram!`). They are pure `&'static str` — no `App`, no
//! registry handle, no state — so a plane names them (`busbar_substrate::metrics::…`) for its own
//! emission sites without reaching into `busbar-core`, and core's `crate::metrics` re-exports each so
//! its `describe_counter!` registrations and every existing `crate::metrics::…` call site resolve
//! unchanged.
//!
//! The RECORDER itself — install, `render()`, the scrape-time gauges, and the per-thread telemetry
//! bank drain — stays in `busbar-core::metrics`: `render()`/`drain_pending()` flush the core-resident
//! `crate::telemetry` bank and `refresh_scrape_gauges` reads the core `App`, so relocating the
//! singleton here would either drop the banked hot-path series from the scrape or drag `App` into the
//! substrate (a dependency cycle). Only the NAMES are neutral, so only the names move. The scrape
//! stays ONE registry, byte-for-byte: these are the same strings, described and emitted from the same
//! sites as before.

/// Routing-policy selections: incremented once per request whose pool resolved a non-default routing
/// policy that produced a ranked order (Prefer / on_error: first). `policy` is the native/transport
/// NAME (a fixed enumeration: cheapest/fastest/least_busy/usage/webhook/script) and `pool` is the
/// configured pool name (bounded at startup) — both safe, bounded labels (no request-derived data).
pub const ROUTE_POLICY_SELECTIONS_TOTAL: &str = "busbar_route_policy_selections_total"; // labels: policy, pool

/// Routing-policy REJECTIONS (the hook's reject verb — a guardrail said no; a 4xx to the caller,
/// no upstream dispatched). `status` is hook-influenced but BOUNDED: the forward seam that
/// constructs `RejectRequest` clamps it to 400..=499 for EVERY producer (wire-normalized or
/// direct-constructed), so the worst-case label fan-out is 100 per (policy, pool) — a safe label.
pub const ROUTE_POLICY_REJECTIONS_TOTAL: &str = "busbar_route_policy_rejections_total"; // labels: policy, pool, status

/// A hook content projection whose serialized size exceeded `limits.hook_content_max_bytes`, so the
/// content was OMITTED WHOLE (never truncated mid-value) and the hook was sent an empty content
/// projection. Unlabeled: the cap is a global ceiling, not a per-hook one. A steady non-zero rate
/// means a content-granted hook is being asked to screen requests it is not being shown; raise the
/// ceiling or narrow what reaches the hook.
pub const HOOK_CONTENT_TRUNCATED_TOTAL: &str = "busbar_hook_content_truncated_total";

/// Same-protocol non-stream responses whose billing-side buffer hit the translate-body cap before the
/// terminal `usage` block, so token usage could not be parsed and the request billed zero despite a
/// full 2xx reaching the client. Incremented once per truncated response. Unlabeled. An operator
/// alerts on a non-zero rate to detect an over-cap billing gap. (The client response is unaffected —
/// it streams verbatim; only the billing side-channel is capped.)
pub const BILLING_TRUNCATED_TOTAL: &str = "busbar_billing_truncated_total"; // no labels

// ── THE RECORDER INSTALL (relocated from busbar-core, verbatim) ──────────────────────────────────
//
// The process-global Prometheus recorder — the opt-in decision, the install itself, the retention
// window, the scrape-independent maintenance drain, the HELP/TYPE registrations and `render()` — is
// `App`-free: it talks only to `metrics-exporter-prometheus` and to the neutral telemetry bank next
// door (`crate::telemetry::flush_to_recorder`). It lives here so a plane's tests can install the SAME
// single registry and read the SAME exposition without naming `busbar-core`. Core's `crate::metrics`
// re-exports every item below at its historical path, so every existing core call site, every metric
// NAME and the exposition format are byte-identical; the `App`-shaped half (`refresh_scrape_gauges`
// and the per-request handle caches) stays in core.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;

use crate::diag_error;
use crate::diag_warn;
use crate::diagnostics::{
    METRICS_MAINTENANCE_THREAD_SPAWN_FAILED, PROMETHEUS_RECORDER_INSTALL_FAILED,
};

// without panicking: `None` = install was attempted and failed; `Some(handle)` = installed. The
// `OnceLock` still serializes the single global `install_recorder()` call across threads/tests.
static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// Whether the operator opted in to metrics (`observability.metrics` present). Set SYNCHRONOUSLY by
/// [`configure`] at startup, before the router is built, while the recorder install itself happens on
/// a background thread — so route mounting reads a settled decision rather than racing the install.
/// Unset ⇒ `false`: a build that never calls `configure` (and every test that does not ask for
/// metrics) has them off.
static ENABLED: OnceLock<bool> = OnceLock::new();

/// Did the operator opt in to metrics? Gates the `/metrics` routes; the recorder's own absence is
/// what makes the hot path free.
pub fn enabled() -> bool {
    ENABLED.get().copied().unwrap_or(false)
}

/// Apply the operator's `observability.metrics` decision. `None` = the block was absent = metrics
/// OFF: no recorder is installed, so every emission macro and bank helper is a no-op, `/metrics` is
/// not mounted, and nothing UNBOUNDED is retained (the per-thread histogram sample buffers this
/// gates via [`retaining`] are dropped rather than buffered). `Some(buffer)` = opted in with a
/// declared retention window.
///
/// NOT a literal "nothing is retained" contract: `CounterSlot::add` stays unconditional even when
/// metrics are off (see its doc comment) — a small, FIXED footprint bounded by thread count x chunk
/// count survives regardless, because counters are cumulative and must not lose pre-install adds.
/// What this rules out is UNBOUNDED, traffic-proportional retention, which is what the histogram
/// buffers were doing before [`retaining`] existed.
///
/// Called once, synchronously, from `run()` after config load. The RECORDER install is deferred to a
/// background thread because its one-time clock calibration (~200 ms) would otherwise delay the
/// listener bind; the enabled flag is set here, in the foreground, so the router sees it.
pub fn configure(buffer: Option<Duration>) {
    let _ = ENABLED.set(buffer.is_some());
    if let Some(buffer) = buffer {
        std::thread::spawn(move || init_with(buffer));
    }
}

/// Should a histogram slot RETAIN a newly-recorded sample right now? Three states, not two:
///
/// * Recorder INSTALLED (`HANDLE` resolved to `Some(_)`) -> `true`. Samples will reach `/metrics`.
/// * Not yet installed but the operator OPTED IN (`HANDLE` unresolved, [`enabled`] true) -> `true`.
///   This is the ~200 ms boot window between `configure` setting `ENABLED` synchronously and
///   `init_with` finishing recorder install on its background thread (see `configure`'s doc
///   comment). An operator who opted in has traffic flowing during that window; gating on recorder
///   installation alone would silently drop it even though the samples WILL be drained once install
///   completes.
/// * Recorder install PERMANENTLY FAILED (`HANDLE` resolved to `Some(None)`), or metrics were never
///   configured / the operator opted out (`HANDLE` unresolved, `enabled()` false) -> `false`.
///   Nothing will ever drain these samples, so a histogram slot must not buffer them.
///
/// Deliberately NOT `recorder_installed()` alone — see the boot-window case above, verified real
/// against `configure`/`init_with`'s actual timing, not assumed.
#[inline]
pub fn retaining() -> bool {
    retaining_from(HANDLE.get().map(Option::is_some), enabled)
}

/// The decision table behind [`retaining`], factored out as a pure function of explicit inputs so
/// it is unit-testable: `HANDLE`/`ENABLED` are process-global `OnceLock`s that can only be set once
/// per test binary, so a test cannot drive the real globals through every state in one run.
///
/// `handle_installed` mirrors `HANDLE.get().map(Option::is_some)`'s three shapes: `None` = `HANDLE`
/// not yet resolved (pre-install, boot window or metrics off); `Some(false)` = resolved to install
/// FAILURE; `Some(true)` = resolved to install SUCCESS. `opted_in` is called ONLY in the `None`
/// (not-yet-resolved) case, matching `retaining`'s lazy call to `enabled()` — it must not be called
/// eagerly, or a test double could observe it being invoked when the real code path wouldn't.
pub fn retaining_from(handle_installed: Option<bool>, opted_in: impl FnOnce() -> bool) -> bool {
    match handle_installed {
        Some(installed) => installed,
        None => opted_in(),
    }
}

/// The canonical busbar metric taxonomy. Names are referenced here so the emission sites and the
/// descriptions below stay in one authoritative list.
///
/// BOUNDED-CARDINALITY CONTRACT — the `pool` label.
/// Every metric below that carries a `pool` label is part of a finite, operator-controlled label
/// space. The value of `pool` MUST be EITHER the canonical name of a pool configured in `app.pools`
/// (resolved via `app.by_model`), OR the fixed sentinel `"unresolved"` used when a request is
/// terminated before its model is resolved to a configured pool (e.g. a governance rejection —
/// 400/401/403/429 — that fires before pool resolution).
///
/// Emission sites MUST NOT pass the raw, client-supplied model string as `pool`. A virtual key with
/// a restricted `allowed_pools` list could otherwise submit unbounded distinct model strings, each
/// rejected yet each minting a brand-new time series, growing the Prometheus registry without bound
/// — a low-effort memory-exhaustion DoS that also bloats every `/metrics` scrape. The label space
/// is bounded BY CONSTRUCTION: |configured pools| + 1. The same rule applies to any request-log /
/// webhook field that mirrors `pool`. The `lane`, `reason`, `disposition`, `outcome`,
/// `ingress_protocol`, `from`, and `to` labels are likewise drawn from fixed enumerations, never
/// from free-form client input.
pub const REQUESTS_TOTAL: &str = "busbar_requests_total"; // labels: ingress_protocol, pool (bounded), outcome
                                                          // UPSTREAM_ATTEMPTS_TOTAL / UPSTREAM_FAILURES_TOTAL metric NAMES moved DOWN to the neutral substrate
                                                          // alongside their hostless emit fns (`busbar_substrate::telemetry`); re-exported here so this file's
                                                          // `describe_counter!` registrations and every `crate::metrics::UPSTREAM_*` call site resolve unchanged.
pub use crate::telemetry::{UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL}; // labels: pool (bounded), lane[, disposition]
pub const BREAKER_TRIPS_TOTAL: &str = "busbar_breaker_trips_total"; // labels: pool (bounded), lane
pub const FAILOVERS_TOTAL: &str = "busbar_failovers_total"; // labels: pool (bounded), reason
pub const REQUEST_DURATION_SECONDS: &str = "busbar_request_duration_seconds"; // histogram; labels: ingress_protocol, pool (bounded)
pub const TRANSLATIONS_TOTAL: &str = "busbar_translations_total"; // labels: from, to

// Per-plane request families for the MOUNTED (non-model) planes — MCP and A2A. Kept SEPARATE from
// the two families above precisely so the model-plane series `busbar_requests_total` /
// `busbar_request_duration_seconds` stay byte-for-byte label-identical to v1.5.4 (which had no
// `plane` label and knew only the model plane). A pure-LLM deployment never emits these, so its
// `/metrics` exposition is unchanged; a deployment that mounts MCP/A2A gets per-plane counts here
// via `sum by (plane)` without ever touching the pre-existing model series' label set.
pub const PLANE_REQUESTS_TOTAL: &str = "busbar_plane_requests_total"; // labels: plane, ingress_protocol, pool (bounded), outcome
pub const PLANE_REQUEST_DURATION_SECONDS: &str = "busbar_plane_request_duration_seconds"; // histogram; labels: plane, ingress_protocol, pool (bounded)

// The ROUTE_POLICY_{SELECTIONS,REJECTIONS}_TOTAL metric NAMES moved DOWN to the neutral substrate
// (`busbar_substrate::metrics`) so the LLM plane's `pipeline.rs` emission sites name them via the ABI;
// re-exported here so the `describe_counter!` registrations below and every `crate::metrics::ROUTE_*`
// call site resolve unchanged. Pure `&str` — no registry moved, scrape byte-identical.
// ROUTE_POLICY_* are defined at the top of this module.

// Request-log webhook deliveries DROPPED because the in-flight delivery semaphore was saturated (the
// webhook endpoint is slow/unreachable and the bounded delivery pool is full). Incremented once per
// dropped log. Unlabeled — the drop is a global backpressure condition, not per-request. An operator
// alerts on a non-zero rate to detect "the webhook is overwhelmed and logs are being shed silently."
pub const WEBHOOK_LOGS_DROPPED_TOTAL: &str = "busbar_webhook_logs_dropped_total"; // no labels

// Request-log FILE appends DROPPED because that sink's in-flight append cap was saturated (the
// filesystem is slow/stalled — a full disk, a hung NFS/EBS mount — and the bounded blocking-append
// pool is full). Incremented once per dropped log, the exact counterpart of
// `WEBHOOK_LOGS_DROPPED_TOTAL` for the other request-log sink. Unlabeled: like the webhook's, the
// drop is a global backpressure condition, not per-request. Alert on a non-zero rate to detect
// "the request-log file sink is shedding lines."
pub const FILE_LOGS_DROPPED_TOTAL: &str = "busbar_file_logs_dropped_total"; // no labels

// A request-log FILE sink crossed `rotate_mb` and was rolled over by RENAMING the full file to a
// numbered archive (`<path>.1`, shifting any older archives up) before a fresh file was opened.
// Incremented once per rotation. Unlabeled — rotation is a per-sink lifecycle event, not
// per-request. A security/audit product must never rotate recorded evidence silently: this counter
// is the observable proof that a rotation preserved history via rename rather than discarding it.
pub const FILE_LOGS_ROTATED_TOTAL: &str = "busbar_file_logs_rotated_total"; // no labels

// A request-log FILE sink crossed `rotate_mb` but the archive RENAME failed (e.g. cross-device
// mount, permission, or a racing external process). On this path the sink deliberately keeps
// APPENDING to the current (over-size) file rather than truncating it — truncation would destroy
// unarchived audit data, which is strictly worse than a temporarily oversized file. Incremented
// once per failed rotation attempt; alert on a non-zero rate — it means a sink is not being bounded
// by `rotate_mb` and needs operator attention (disk/permissions on the sink's directory).
pub const FILE_LOGS_ROTATE_FAILED_TOTAL: &str = "busbar_file_logs_rotate_failed_total"; // no labels

// App-retype WEDGE 3: the `busbar_tap_notifications_dropped_total` metric NAME moved to the substrate
// tap fan-out (`busbar_substrate::proxy::proxy_vocab::spawn_bounded_tap`) with core's `spawn_bounded_tap`
// retirement — the ONE shared 1024-permit tap gate now lives there and emits this counter byte-identically,
// so core no longer names the const (the string is pinned equal substrate-side).

// The HOOK_CONTENT_TRUNCATED_TOTAL metric NAME moved DOWN to `busbar_substrate::metrics` so the LLM
// plane's `hooks.rs` emission site names it via the ABI; re-exported here so `crate::metrics::…` call
// sites resolve unchanged. Unlabeled counter: a hook content projection whose serialized size
// exceeded `limits.hook_content_max_bytes`, so the content was OMITTED WHOLE (never truncated
// mid-value) and the hook was sent an empty content projection. A steady non-zero rate means a
// content-granted hook is being asked to screen requests it is not being shown; raise the ceiling or
// narrow what reaches the hook.
// HOOK_CONTENT_TRUNCATED_TOTAL is defined at the top of this module.

// A same-protocol 2xx response body the usage tap could not decode into token usage, so the request
// was billed 0 tokens. Labeled by `protocol` (the ingress protocol, a fixed enumeration) and
// `reason` (`unknown_protocol` / `bad_json` / `decode`). This is the per-request VOLUME signal for the
// tap-decode fault class: the log site is warn-once-per-(protocol,reason) to avoid per-request spam,
// so this counter — not the log — is what an operator alerts on. A steady non-zero rate means a live
// protocol/dialect the tap reader cannot decode, i.e. silent under-billing.
//
// The metric name and its warn-once latch (`usage_tap_decode_fail_should_warn`) relocated to
// `busbar_substrate::handlers` with the `OperationHandler::extract_usage` default that increments it;
// re-exported here so the `describe_counter!` registration below and the doc-links in
// `handlers::mod` still resolve at `crate::metrics::BILLING_TAP_DECODE_FAIL_TOTAL`.
pub use busbar_substrate_values::handlers::BILLING_TAP_DECODE_FAIL_TOTAL;

// A request/task denied entry by a `limits::admission::AdmissionGate` because its permit cap was
// saturated. Labeled `gate` = the gate's fixed name (`"inbound"`/`"webhook"`/`"tap"`/
// `"request-log-file"` today — one
// per `AdmissionGate::new` call site in the binary, so the label space is bounded at compile time,
// never client-influenced). This is the GATE-level mechanic counter shared by every admission site;
// it does NOT replace a site's own policy-specific drop counter (e.g. `WEBHOOK_LOGS_DROPPED_TOTAL`,
// `TAP_NOTIFICATIONS_DROPPED_TOTAL`) where one already exists — those stay, so existing dashboards
// and alerts keep working unchanged. This counter exists so every gate (including ones with no
// bespoke counter of their own, like the inbound cap) is uniformly observable.
pub const ADMISSION_DENIED_TOTAL: &str = "busbar_admission_denied_total"; // labels: gate

// The BILLING_TRUNCATED_TOTAL metric NAME moved DOWN to `busbar_substrate::metrics` so the LLM plane's
// `response_body.rs` emission site names it via the ABI; re-exported here so the `init_with` pre-touch
// (below), the `describe_counter!` registration, and every `crate::metrics::…` call site resolve
// unchanged. Unlabeled counter: same-protocol non-stream responses whose billing-side buffer hit the
// translate-body cap before the terminal `usage` block, so token usage could not be parsed and the
// request billed zero despite a full 2xx reaching the client. An operator alerts on a non-zero rate to
// detect an over-cap billing gap. (The client response is unaffected — only the billing side-channel
// is capped.)
// BILLING_TRUNCATED_TOTAL is defined at the top of this module.

// The write-behind metering accumulator (`pending_metering`) was at its cap when a NEW
// `(key_id, bucket, model, provider)` cell arrived — a sustained governance-store outage with diverse
// keys/models. The arriving cell's counts are COALESCED into a per-bucket overflow sentinel rather
// than dropped, so billable token/request totals are preserved for the day and only per-key/model
// ATTRIBUTION is collapsed. Incremented once per coalesced cell. Unlabeled. A non-zero rate means the
// store has been unreachable long enough to overflow the cap; usage is not lost but its attribution is
// degrading, so alert and restore the store. (Contrast BILLING_TRUNCATED_TOTAL, which is a genuine
// per-response gap.)
pub const METERING_PENDING_COALESCED_TOTAL: &str = "busbar_metering_pending_coalesced_total"; // no labels

// A plugin HTTP-endpoint route's INBOUND request header count exceeded
// `plugin_routes::MAX_PLUGIN_HEADERS` before the projection was forwarded to the plugin's
// `handle_http`. The projection is still sent (truncated, never silently — see
// `plugin_routes::PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER`, which the plugin can inspect), so this
// counts a plugin having made an auth/governance/routing decision on an INCOMPLETE header set.
// Unlabeled: a global signal, not per-route. A steady non-zero rate means either a client's header
// count is routinely large (raise the cap) or a route needs investigating for hostile flooding.
pub const PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL: &str =
    "busbar_plugin_request_headers_truncated_total"; // no labels

// A plugin HTTP-endpoint route's OUTBOUND response header count exceeded
// `plugin_routes::MAX_PLUGIN_HEADERS`. Unlike the request-side counter above, this response reaches an
// EXTERNAL client, so the OWNER PRINCIPLE (a consumer never receives a silently-shortened data set)
// leaves no truncate-and-mark fallback: the whole response is REJECTED (502) instead, and this counter
// records the rejection. Unlabeled: a global signal. A non-zero rate means a plugin is emitting an
// over-cap header set — either the plugin is hostile/buggy (investigate the route named in the
// accompanying error log) or the cap needs raising.
pub const PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL: &str =
    "busbar_plugin_response_headers_rejected_total"; // no labels

// ── Scrape-time gauges (new in feat/observability-depth) ────────────────────────────────────────
//
// These are REFRESHED each scrape from in-process reads (governance SQLite + breaker state).
// They are NOT emitted on the hot request path and carry no request-time client data.
//
// CARDINALITY PROOF:
// * `busbar_key_spend_cents` / `busbar_key_budget_remaining_cents` / `busbar_key_tokens_total`:
//   label `key` = the virtual-key id (a `vk_<16-hex-char>` prefix derived from the secret hash).
//   The label space = {all virtual keys ever created}, which is strictly bounded by the operator
//   (keys are minted via the admin API; an operator can only create as many as they choose). The
//   raw bearer secret is NEVER used as a label value; only the operator-visible `id` field is used.
//   Client requests cannot mint new keys or introduce new label values.
//
// * `busbar_lane_state`: labels `pool` (configured pool name set — bounded by Cargo at startup) and
//   `lane` (the lane's configured MODEL string — bounded by N = number of configured lanes, a
//   startup constant; identical to the `lane` label on the proxy engine counters so the gauge and
//   counters PromQL-join). Neither label can be influenced by a client request.

/// Per-virtual-key spend in cents for the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id (operator-bounded). Only emitted when governance is enabled.
pub const KEY_SPEND_CENTS: &str = "busbar_key_spend_cents";

/// Accumulated tokens consumed by each virtual key in the current budget window. Scrape-time gauge.
/// Label: `key` = virtual-key id. Only emitted when governance is enabled.
pub const KEY_TOKENS_TOTAL: &str = "busbar_key_tokens_total";

/// Per-(bucket, model, tier) token counters for the bucket's CURRENT budget window. Scrape-time
/// gauge, derived from the token ledger. `bucket` is a virtual-key id or `group:<name>` (both
/// operator-bounded); `model` is bounded by the configured fleet (an ad-hoc passthrough model is
/// only possible with pricing off); `tier` is one of the four fixed pricing tiers. Key-bucket
/// series additionally echo the key's mint-time labels, so external dashboards can
/// `sum by (team)` without busbar knowing what "team" means.
pub const BUCKET_TOKENS: &str = "busbar_bucket_tokens";

/// DERIVED spend (cents, abstract minor units) per BUDGET-GROUP bucket for its current window,
/// recomputed from the token ledger x the CURRENT rate card at scrape time (reprice-on-read).
/// Label: `bucket` = `group:<name>`. Key-bucket spend stays on `busbar_key_spend_cents`.
pub const BUCKET_SPEND_CENTS: &str = "busbar_bucket_spend_cents";

/// Cap minus derived spend per BUDGET-GROUP bucket. Label: `bucket` = `group:<name>`. The
/// external-alerting linchpin: Alertmanager fires at 80% burn without busbar shipping any
/// alerting of its own.
pub const BUCKET_BUDGET_REMAINING_CENTS: &str = "busbar_bucket_budget_remaining_cents";

/// Per-(pool, lane-model) circuit-breaker health gauge.
/// Values: 0 = healthy (Closed), 1 = half-open (cooling but probe admitted), 2 = tripped (Open /
/// hard-down). Scrape-time gauge; side-effect-free (does not trigger Open→HalfOpen transitions).
/// Labels: `pool` (configured pool name, bounded) and `lane` (the lane's MODEL string, bounded —
/// matches the proxy engine counter sites so the gauge and counters can be PromQL-joined on `lane`).
pub const LANE_STATE: &str = "busbar_lane_state";

/// Per-(pool, lane-model) availability gauge — the UNIFIED capacity+breaker signal. `1` =
/// the lane's per-(pool, lane) `classify` returns `Ok` (it would admit a request right now); `0` = it
/// returns `Err(_)` for ANY reason (breaker Open, at-capacity, dead, budget, probe-in-flight). This
/// is rendered from the SAME `classify` taxonomy routing dispatches on, so the gauge cannot drift from
/// behaviour. The ORTHOGONAL axes stay separately legible: `busbar_lane_state` exposes the
/// breaker and `busbar_lane_available_permits` exposes capacity, so an Open+at-capacity lane is not
/// hidden behind this one collapsed bool. Replaces the ad-hoc `busbar_lane_at_capacity`. Same
/// `pool`/`lane` label convention as `busbar_lane_state`.
pub const LANE_AVAILABLE: &str = "busbar_lane_available";

/// Per-(pool, lane-model) recovery hint in milliseconds, rendered from the SAME
/// `Unavailable::recovery_hint_ms` that feeds `Retry-After`/least_bad. `0` when the lane is available
/// or the reason has no self-recovery basis (dead/budget); otherwise the honest lower bound on when
/// the lane could next serve (breaker `until`, the at-capacity floor, etc.). Same label convention.
pub const LANE_RECOVERY_HINT_MS: &str = "busbar_lane_recovery_hint_ms";

/// Per-(pool, lane-model) in-flight request count (held concurrency permits) — the depth companion to
/// `busbar_lane_available`. Emitted for every lane. Same label convention as the gauges above.
pub const LANE_INFLIGHT: &str = "busbar_lane_inflight";

/// Per-(pool, lane-model) available concurrency permits, for BOUNDED lanes only (an unbounded lane
/// counts nothing, so it emits no sample here). The capacity depth signal (`0` = saturated), kept
/// INDEPENDENT of `busbar_lane_available` so the capacity axis stays legible. Same label
/// convention as the gauges above.
pub const LANE_AVAILABLE_PERMITS: &str = "busbar_lane_available_permits";

/// Per-pool count of requests currently PARKED in the `on_exhausted: queue` bounded wait. Rendered
/// at scrape time from the live `state::QueuedDepth` source, so the queue implementation only
/// increments/decrements a counter and never touches `metrics.rs`. Label
/// `pool` = configured pool name (bounded), the same convention as the lane gauges.
pub const POOL_QUEUED: &str = "busbar_pool_queued";

/// Prometheus text exposition format content-type (version 0.0.4), returned by the `/metrics`
/// scrape handler. Defined as a constant so the string is not duplicated across handler and tests.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Install the global Prometheus recorder. Idempotent: safe to call once at startup and
/// repeatedly from tests (the global recorder can only be installed once per process, so the
/// `OnceLock` guards it). Also registers HELP/TYPE descriptions for the taxonomy.
/// Install the recorder for an operator who OPTED IN, retaining `buffer` seconds of observations.
///
/// `buffer` is `observability.metrics.buffer_seconds` — a REQUIRED config field, so this value is
/// always one a human named. It sets both halves of the retention contract: the rolling-summary
/// window (quantiles cover the last `buffer`; anything older is dropped) and, divided by
/// [`SUMMARY_BUCKETS`], how often parked raw samples are folded into it — that quotient is the
/// bucket width AND the [`spawn_maintenance`] tick.
///
/// NOT called unless `observability.metrics` is present. With no recorder installed, every emission
/// macro and every bank helper is a no-op against the default recorder, so an operator who did not
/// opt in records nothing and retains nothing.
pub fn init_with(buffer: Duration) {
    // Retention is split across a few rolling buckets so quantiles degrade smoothly as the window
    // slides, instead of the whole window vanishing at once on rollover. The buckets SUM to
    // `buffer`, which is the operator's declared retention.
    let bucket = buffer
        .checked_div(SUMMARY_BUCKETS.get())
        .unwrap_or(buffer)
        .max(Duration::from_millis(1));
    // The global recorder can only be installed once per process, so the `OnceLock` runs this
    // initializer exactly once and serializes concurrent callers (startup + tests). On install
    // FAILURE — typically because another library already installed a global recorder — we log and
    // store `None` rather than panicking: this runs on a background thread (main.rs) where a
    // panic would be silent, leaving `/metrics` empty with no operator-visible cause. Storing `None`
    // degrades gracefully (empty exposition) AND emits an error log so the cause is discoverable.
    HANDLE.get_or_init(|| match build_recorder(bucket) {
        Ok(handle) => {
            describe();
            // Pre-register the unlabeled counter so `/metrics` is non-empty from the first
            // scrape. The exporter renders only touched metrics; without this, a freshly
            // booted gateway that has served no traffic exposes an EMPTY body, and an
            // operator wiring up Prometheus before sending traffic reasonably concludes
            // the endpoint is broken (found by the acceptance harness, 2026-07-09).
            // Only the unlabeled family is pre-touched: labeled families would require
            // inventing label values, which the cardinality contract above forbids. The
            // labeled gauges appear on the first scrape via `refresh_scrape_gauges`.
            metrics::counter!(BILLING_TRUNCATED_TOTAL).absolute(0);
            // NOT pre-registered: unlike BILLING_TRUNCATED_TOTAL (a 1.5.5 series), the
            // write-behind coalesce sentinel must not appear on `/metrics` until it is actually
            // incremented (a sustained store outage overflowed the accumulator). Pre-touching it
            // at 0 would expose the series on an idle 1.5.5-style config, which 1.5.5 never did;
            // it is still described (below) and rendered with HELP/TYPE the moment it fires.
            spawn_maintenance(bucket);
            Some(handle)
        }
        Err(e) => {
            diag_error!(
                PROMETHEUS_RECORDER_INSTALL_FAILED,
                "prometheus recorder install failed; /metrics will be empty: {e}"
            );
            None
        }
    });
}

/// Number of rolling buckets the retention window is split across (see [`init_with`]).
const SUMMARY_BUCKETS: std::num::NonZeroU32 = match std::num::NonZeroU32::new(3) {
    Some(n) => n,
    None => unreachable!(),
};

/// How long a gauge whose subject no longer exists keeps appearing in the exposition.
///
/// Per-key gauges are only `set` while iterating LIVE keys, so a deleted key's series would
/// otherwise be re-rendered with its final value for the life of the process — `/metrics` grows
/// with the operator's lifetime key churn, and dashboards show a deleted key's spend as current.
///
/// Deliberately its own constant rather than a reuse of the histogram retention window: that window
/// is sized by raw-sample memory cost, and coupling the two would let a memory-budget choice
/// silently decide how long a deleted key lingers. GAUGES ONLY — expiring a counter would reset it
/// and break `rate()`, and expiring a histogram would discard its summary.
///
/// A live series can never be caught by this: `refresh_scrape_gauges` runs inside `render`, so every
/// live gauge is re-set microseconds before it is rendered regardless of the scrape interval.
pub const GAUGE_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Build the Prometheus recorder with the operator's retention window and install it globally.
/// Split out of [`init_with`] so the fallible builder chain reads in one place.
fn build_recorder(
    bucket: Duration,
) -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    recorder_builder(bucket, GAUGE_IDLE_TIMEOUT)?.install_recorder()
}

/// The builder itself, with the idle timeout as a parameter so a test can drive expiry on a short
/// window instead of the shipped one. Installing is global and once-per-process; building is not,
/// which is what makes the reaping behaviour testable at all.
pub fn recorder_builder(
    bucket: Duration,
    gauge_idle: Duration,
) -> Result<PrometheusBuilder, metrics_exporter_prometheus::BuildError> {
    Ok(PrometheusBuilder::new()
        .set_bucket_duration(bucket)?
        .set_bucket_count(SUMMARY_BUCKETS)
        .idle_timeout(metrics_util::MetricKindMask::GAUGE, Some(gauge_idle)))
}

/// Test-only entry point: install the recorder with a retention window long enough that no test's
/// samples age out mid-assertion. Production ALWAYS goes through [`init_with`] with the operator's
/// configured `buffer_seconds`; there is deliberately no arg-less initializer outside tests, so no
/// build path can install metrics without a named retention window.
#[cfg(any(test, feature = "test-support"))]
pub fn init() {
    let _ = ENABLED.set(true);
    init_with(Duration::from_secs(3600));
}

// ── SCRAPE-INDEPENDENT MAINTENANCE ───────────────────────────────────────────────────────────────
//
// THE INVARIANT: an observation costs BOUNDED memory whether or not anyone ever scrapes `/metrics`.
//
// Two layers buffer raw per-request observations on the way to their bounded aggregate form:
//   1. the telemetry BANK — each thread appends one `f64` per request to its own sample `Vec`
//      (`telemetry::HistogramSlot::record`), drained by `telemetry::flush_to_recorder`;
//   2. the Prometheus recorder — `metrics-exporter-prometheus` parks every histogram sample handed
//      to it in an `AtomicBucket` (a linked list of 64-slot blocks, ~8.4 B/sample) until something
//      calls `run_upkeep()`/render, which folds them into the FIXED-SIZE rolling summary.
//
// Both drains used to happen ONLY inside `render()` — i.e. only when a scrape arrived. A gateway
// nobody scrapes therefore retained one f64 per request FOREVER: RSS grew linearly with total
// requests served (measured: ~23 B/request; 18.1 M requests → +389 MiB, with no plateau and no
// release when the load stopped), instead of tracking the live working set. That is a leak by any
// ordinary definition — `/metrics` is an OPTIONAL endpoint, and memory must not depend on whether
// an operator wired Prometheus up (or on whether their scrape job is currently healthy).
//
// The fix is one choke point: a maintenance tick that performs EXACTLY the same two drains a scrape
// performs, on a timer, so the buffered depth is bounded by one interval's traffic instead of by the
// process lifetime. It changes no metric value: `_sum`/`_count` are cumulative either way, and the
// quantile window becomes a true rolling window (samples land in the bucket matching when they were
// observed) rather than every sample since the last scrape being crammed into the scrape instant.

// The tick cadence is DERIVED from the operator's `buffer_seconds` rather than picked here: it is
// one rolling bucket (`buffer / 3`), so parked raw samples never exceed a third of the declared
// retention window, and every sample lands in the bucket its own timestamp belongs to.

/// Fold every buffered observation into its bounded aggregate storage — the drain half of a scrape,
/// without rendering. Idempotent and safe to call at any time (a no-op before the recorder is
/// installed, and when nothing is buffered).
pub fn drain_pending() {
    // Test-only: keep `run_upkeep`'s bucket frees on the same thread as the drain that fed them —
    // see `telemetry::drain_serial`. Re-entrant, so the nested `flush_to_recorder` is free.
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    // Outer `None` = `init()` has not run; inner `None` = install failed. Both mean there is no
    // recorder to drain into, and the bank's own emit helpers are no-ops in that state.
    let Some(Some(handle)) = HANDLE.get() else {
        return;
    };
    // 1. bank → recorder (per-thread sample buffers + counter deltas)
    crate::telemetry::flush_to_recorder();
    // 2. recorder's per-sample buckets → fixed-size distributions
    handle.run_upkeep();
}

/// Start the maintenance tick. Called once, from the successful branch of [`init`], so every build
/// that has a recorder also has the drain — no configuration, no operator action, no dependency on
/// anyone scraping. A dedicated OS thread (not a Tokio task) because the drain is synchronous and
/// takes the bank's locks: it must never occupy an executor worker, and it must keep running even
/// if the runtime is saturated. Best-effort: if the thread cannot be spawned we log and continue —
/// the pre-existing scrape-driven drain still applies.
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
    // Scrape-time gauges.
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

/// True once the global Prometheus recorder is INSTALLED (not merely that `init()` was attempted).
/// Gating handle caching on this guarantees a cached handle can never be bound to the no-op recorder
/// that stands in before install.
#[inline]
pub fn recorder_installed() -> bool {
    matches!(HANDLE.get(), Some(Some(_)))
}

/// Render the current Prometheus exposition text. Empty until `init()` has run.
///
/// Flushes the TELEMETRY BANK (per-thread hot-path cells; see `telemetry.rs`) into the recorder
/// first, so every scrape — and every test that reads the exposition — observes up-to-date totals
/// for the banked hot-path counters/histograms alongside the macro-emitted ones.
pub fn render() -> String {
    // Test-only: a scrape is a drain too — see `telemetry::drain_serial`.
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    // Outer `None` = `init()` not yet run; inner `None` = recorder install failed. Both render an
    // empty exposition rather than panicking.
    match HANDLE.get() {
        Some(Some(h)) => {
            crate::telemetry::flush_to_recorder();
            h.render()
        }
        _ => String::new(),
    }
}

// ─── PER-REQUEST HANDLE CACHE (relocated from busbar-core, verbatim) ───────────────────────────────
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
// These helpers name only the NEUTRAL metric-name consts above, `recorder_installed()`, and the
// `metrics` macros — no `App`, no engine handle — so they live beside the recorder install they feed.
// Core's `crate::metrics` re-exports each at its historical `crate::metrics::…` path, and the `&App`
// telemetry wrappers (now `busbar_substrate::telemetry::request_finished`, behind the neutral
// `TelemetrySource` seam) call them unchanged, so the emitted series are byte-identical.
//
// Correctness vs. the recorder-install ordering the module contract calls out (a handle minted before
// `init()` installs the recorder binds to the no-op recorder FOREVER): the cache is populated ONLY
// once the recorder is installed (`HANDLE == Some(Some(_))`). Before that — `init()` not yet run, or
// install failed — these helpers fall through to the plain macro (itself a no-op against the default
// recorder), caching nothing.

/// Unit separator joining label values into the compact cache key — a control byte that cannot occur
/// in an ingress-protocol or pool name, so `"a\x1fb"` can never collide with `"a"` + `"\x1fb"`.
const CACHE_KEY_SEP: char = '\u{1f}';

static REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> = OnceLock::new();
static DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> = OnceLock::new();
// The mounted plane consumers' families keep their OWN caches: the `plane` label makes their key
// space distinct from the primary-plane series above, and keeping them separate is what lets the
// primary-plane series stay label-identical to v1.5.4.
static PLANE_REQUESTS_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Counter>>> =
    OnceLock::new();
static PLANE_DURATION_HANDLES: OnceLock<RwLock<HashMap<Box<str>, metrics::Histogram>>> =
    OnceLock::new();

/// Increment `REQUESTS_TOTAL` for `(ingress_protocol, pool, outcome)` via a CACHED counter handle —
/// no registry lookup and no per-request `Label`/`Key` construction on the steady-state path. Falls
/// back to the plain macro until the recorder is installed (see the cache-module note above).
/// Byte-for-byte the same series and value the macro produced. This is the primary plane's family
/// and carries NO `plane` label, so its exposition is identical to v1.5.4 (`incr_plane_requests_total`
/// is the mounted-plane-consumer counterpart).
pub fn incr_requests_total(ingress_protocol: &str, pool: &str, outcome: &'static str) {
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

/// Increment `PLANE_REQUESTS_TOTAL` for `(plane, ingress_protocol, pool, outcome)` — the
/// mounted-plane-consumer counterpart of [`incr_requests_total`]. SEPARATE family and SEPARATE cache
/// so the primary-plane series stays label-identical to v1.5.4; same cached-handle contract
/// otherwise.
pub fn incr_plane_requests_total(
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
/// histogram handle. Same caching contract as [`incr_requests_total`]; the primary plane's family,
/// with NO `plane` label (see [`record_plane_request_duration`] for the mounted-plane-consumer
/// counterpart).
pub fn record_request_duration(ingress_protocol: &str, pool: &str, seconds: f64) {
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
/// mounted-plane-consumer counterpart of [`record_request_duration`], in a SEPARATE family/cache.
pub fn record_plane_request_duration(
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

// ─── SCRAPE-TIME GAUGE COMPOSITION (relocated from busbar-core behind a neutral trait) ─────────────
//
// `refresh_scrape_gauges` composes and emits every scrape-time gauge family (per-key spend/tokens,
// group-bucket spend/remaining/tokens, and the per-(pool,lane) health/availability gauges). The BULK
// — the label building, the gauge `set()` emits, the lane-state derivation, the pool/model loops and
// `emit_lane_gauges` — needs only bounded SCALARS plus the two already-neutral engine/store views, so
// it lives here behind the [`ScrapeSource`] seam. `busbar-core` keeps a THIN `impl ScrapeSource for
// App` (the `App` field reads, the fallible governance/store projections, their diagnostics, and the
// per-key gauge-limit cap) and a one-line `crate::metrics::refresh_scrape_gauges(app)` call site. No
// plane/money TYPE crosses the boundary and the rendered `/metrics` bytes are unchanged.

/// Per-(model) token tallies for the four fixed pricing tiers, projected off the token ledger by the
/// [`ScrapeSource`] implementor so this crate never names `busbar_api::UNIT_*` or the ledger types.
#[derive(Clone, Copy, Default)]
pub struct TierTokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// The four `(tier-label, value)` rows one [`TierTokens`] renders as `busbar_bucket_tokens` samples,
/// in the historical emission order (`input`, `output`, `cache_read`, `cache_write`).
fn tier_rows(t: &TierTokens) -> [(&'static str, u64); 4] {
    [
        ("input", t.input),
        ("output", t.output),
        ("cache_read", t.cache_read),
        ("cache_write", t.cache_write),
    ]
}

/// One virtual key's scrape identity: the operator-visible id + its mint-time labels. The spend/token
/// SCALARS are fetched separately, per key, via [`ScrapeSource::key_usage`] so a key that vanished
/// between listing and reading is skipped without a wasted projection.
pub struct ScrapeKey {
    pub id: String,
    pub labels: Vec<(String, String)>,
}

/// Derived current-window usage scalars for one virtual key (`usage.spend_cents` / `usage.tokens`).
pub struct KeyUsage {
    pub spend_cents: i64,
    pub tokens: u64,
}

/// One budget-group enforcement bucket's scrape identity: the ledger id, the group name, its window,
/// and any budget cap. Spend + per-model tokens are fetched separately, per bucket.
pub struct ScrapeGroupBucket {
    pub bucket_id: String,
    pub group_name: String,
    pub window: &'static str,
    pub budget_cap: Option<i64>,
}

/// The NEUTRAL scalar seam the scrape-time gauge machinery reads. The substrate NAMES this trait and
/// composes/emits every gauge; `busbar-core` implements it as a thin set of `App` field reads
/// (`impl ScrapeSource for App`). No plane/money TYPE crosses the boundary — only bounded scalar
/// projections plus the two already-neutral engine/store views — so the composition lives here without
/// a substrate→core cycle and the rendered `/metrics` bytes stay byte-identical.
pub trait ScrapeSource {
    /// Is governance enabled? Gates the per-key + group-bucket gauge families (was `app.governance`).
    fn governance_enabled(&self) -> bool;
    /// Every virtual key to emit a per-key gauge for, ALREADY BOUNDED to the per-key gauge limit and
    /// diagnosed (an empty vec on a store error). The implementor owns the `key_gauge_limit` cap and
    /// its warn-once latch, so this crate emits gauges for exactly the returned keys.
    fn scrape_keys(&self) -> Vec<ScrapeKey>;
    /// Derived spend/token scalars for one key. `None` = the key vanished or its read failed (logged
    /// by the implementor) — the whole key is skipped, matching the pre-refactor `continue`.
    fn key_usage(&self, id: &str, now: u64) -> Option<KeyUsage>;
    /// Per-(model) all-time-window (`WINDOW_TOTAL`) token tallies for one key's attribution bucket.
    fn key_model_tokens(&self, id: &str, now: u64) -> Vec<(String, TierTokens)>;
    /// Every budget-group bucket to emit gauges for, flattened over `(group, bucket)`.
    fn scrape_group_buckets(&self) -> Vec<ScrapeGroupBucket>;
    /// DERIVED spend (cents, request fee included) for one group bucket in its window. `None` = the
    /// ledger read failed (logged) — the bucket is skipped, matching the pre-refactor `continue`.
    fn group_bucket_spend(&self, bucket_id: &str, window: &str, now: u64) -> Option<i64>;
    /// Per-(model) token tallies for one group bucket in its window.
    fn group_model_tokens(
        &self,
        bucket_id: &str,
        window: &str,
        now: u64,
    ) -> Vec<(String, TierTokens)>;
    /// The lane-health runtime (breaker snapshots, per-(pool,lane) classify/cooldown). Already a
    /// neutral substrate trait object.
    fn lane_runtime(&self) -> &dyn crate::store::LaneRuntime;
    /// The data-plane routing tables (pool membership, model indices, queue depth, lane models).
    /// Already a neutral substrate trait object.
    fn engine_view(&self) -> &dyn crate::plane_host::EngineTablesView;
}

/// Refresh all scrape-time gauges from the [`ScrapeSource`]'s in-process reads. Called on every
/// `/metrics` scrape (via core's `crate::metrics::refresh_scrape_gauges` wrapper) so values are
/// current at observation time. Governance families are skipped when governance is disabled; pool and
/// lane label spaces are bounded by operator configuration; virtual-key ids are bounded by the set of
/// keys the admin created. No client-supplied label values are ever emitted.
pub fn refresh_scrape_gauges<S: ScrapeSource + ?Sized>(src: &S) {
    let now = crate::store::now();

    // ── Governance: per-key spend, tokens, and per-(model,tier) bucket tokens ───────────────────
    if src.governance_enabled() {
        // The key list is ALREADY bounded to `key_gauge_limit` and diagnosed by the implementor.
        for key in src.scrape_keys() {
            // `None` = the key vanished between list and read, or the read failed (logged in core);
            // skip the WHOLE key (spend, tokens, and its per-model bucket tokens).
            let Some(usage) = src.key_usage(&key.id, now) else {
                continue;
            };
            // key label = the operator-visible virtual-key id (`vk_<hex>`), never the bearer secret.
            // The key's MINT-TIME labels are echoed onto every series so external Grafana can
            // `sum by (team)` WITHOUT busbar knowing what "team" means.
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
            // Per-(bucket, model, tier) token gauges from the key bucket's all-time-window ledger.
            for (model, tokens) in src.key_model_tokens(&key.id, now) {
                for (tier, v) in tier_rows(&tokens) {
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

        // ── GROUP buckets: derived spend + remaining + per-(model, tier) tokens ─────────────────
        for bucket in src.scrape_group_buckets() {
            let Some(spend_cents) = src.group_bucket_spend(&bucket.bucket_id, bucket.window, now)
            else {
                continue;
            };
            let dims = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                let mut labels = vec![
                    metrics::Label::new("bucket", bucket.bucket_id.clone()),
                    metrics::Label::new("group", bucket.group_name.clone()),
                    metrics::Label::new("window", bucket.window),
                ];
                for (k, v) in extra {
                    labels.push(metrics::Label::new(*k, v.clone()));
                }
                labels
            };
            metrics::gauge!(BUCKET_SPEND_CENTS, dims(&[])).set(spend_cents as f64);
            // Budget-remaining: only for a bucket that carries a `budget` cap.
            if let Some(cap) = bucket.budget_cap {
                let remaining = cap.saturating_sub(spend_cents).max(0);
                metrics::gauge!(BUCKET_BUDGET_REMAINING_CENTS, dims(&[])).set(remaining as f64);
            }
            for (model, tokens) in src.group_model_tokens(&bucket.bucket_id, bucket.window, now) {
                for (tier, v) in tier_rows(&tokens) {
                    metrics::gauge!(
                        BUCKET_TOKENS,
                        dims(&[("model", model.clone()), ("tier", tier.to_string())])
                    )
                    .set(v as f64);
                }
            }
        }
    }

    // ── Lane health: per-(pool, lane-index) breaker state ──────────────────────────────────────
    // Pure atomic reads (dead flag, aggregate usability, per-(pool,lane) cooldown/classify) — no FSM
    // transitions triggered. The `lane` label value is the lane's MODEL string (matching the
    // request-counter emission sites so gauge and counters PromQL-join), not a numeric index.
    let store = src.lane_runtime();
    let view = src.engine_view();
    let mut snap_cache: std::collections::HashMap<usize, crate::store::LaneSnapshot> =
        std::collections::HashMap::new();
    for (pool_name, member_idxs) in view.pools() {
        // Render the LIVE per-pool `on_exhausted: queue` park depth (0 when a pool never queues).
        metrics::gauge!(POOL_QUEUED, "pool" => pool_name.to_string())
            .set(view.queued_depth(pool_name) as f64);
        for lane_idx in member_idxs {
            let snap = snap_cache
                .entry(lane_idx)
                .or_insert_with(|| store.snapshot(lane_idx, now));
            let pool_cooldown = store.cooldown_remaining_in(pool_name, lane_idx, now);
            let state_val: f64 = if snap.dead || (pool_cooldown > 0 && !snap.usable) {
                2.0 // hard-down or all cells Open/tripped
            } else if pool_cooldown > 0 {
                1.0 // HalfOpen: this cell has a non-zero cooldown but the lane still admits
            } else {
                0.0 // Closed / healthy
            };
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
            let avail = store.classify(pool_name, lane_idx, now);
            emit_lane_gauges(pool_name, &lane_label, snap, &avail, now);
        }
    }

    // Direct-model lanes (reachable via `by_model` routing, no pool required) get a lane-state gauge
    // too, labeled with the model name as `pool` — the same convention the counters use for
    // model-routed traffic — so gauge and counters PromQL-join.
    for (model, lane_idx) in view.model_indices() {
        let snap = snap_cache
            .entry(lane_idx)
            .or_insert_with(|| store.snapshot(lane_idx, now));
        let cooldown = store.cooldown_remaining_in("", lane_idx, now);
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
        let avail = store.classify("", lane_idx, now);
        emit_lane_gauges(model, &lane_model, snap, &avail, now);
    }
}

/// Emit the per-(pool, lane) availability + depth gauges. `avail` is the SAME
/// `classify(pool, lane, now)` verdict routing dispatches on, so `busbar_lane_available` (1=Ok/0=Err)
/// and `busbar_lane_recovery_hint_ms` (from `Unavailable::recovery_hint_ms`, 0 when available or no
/// self-recovery basis) can never drift from behaviour. `busbar_lane_inflight` is always emitted;
/// `busbar_lane_available_permits` only for BOUNDED lanes. Shared by the pool loop and the by_model
/// loop so the two label conventions stay identical to `LANE_STATE`.
fn emit_lane_gauges(
    pool_label: &str,
    lane_label: &str,
    snap: &crate::store::LaneSnapshot,
    avail: &Result<(), crate::store::Unavailable>,
    now: u64,
) {
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

/// THE RECORDER BUILDER'S INTERNALS, revealed to a TEST BUILD ONLY.
///
/// `recorder_builder` is deliberately split out of the install so a test can drive gauge expiry on a
/// short window instead of the shipped one, and `GAUGE_IDLE_TIMEOUT` is the shipped window that same
/// battery pins. Installing is global and once-per-process; BUILDING is not, which is what makes the
/// reaping behaviour testable at all — so the two are reachable from a test build and from nowhere
/// else, on the same test/`test-support` axis the rest of the test surface uses.
#[cfg(any(test, feature = "test-support"))]
pub mod recorder_internals {
    pub use super::{recorder_builder, GAUGE_IDLE_TIMEOUT};
}
