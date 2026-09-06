// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Process-wide operational limits ("NEVER CODED CAPS"), installed from the resolved config
//! (`config::LimitsResolved`) at startup AND on every config apply/reload (the config plane
//! refreshes them live), read by the use sites that live too deep in a call stack to thread
//! `App`/`&self` through.
//!
//! Each accessor returns the operator-configured value when `install` has run, and otherwise the
//! HISTORICAL hardcoded default (the same `config::DEFAULT_*` const the serde defaults use). So a
//! unit test that never calls `install` sees byte-for-byte today's behavior, and a double-`install`
//! (only `main` calls it) is a no-op rather than a panic.
//!
//! Values threaded explicitly (the upstream client timeout/pool-idle, the axum `DefaultBodyLimit`,
//! the inbound concurrency layer, the TLS handshake bound, and the store's hard-down /
//! retry-after ceiling) do NOT live here — they reach their site directly from `RootCfg.limits`.
//! This module is only for the sites without such a path.

pub(crate) mod admission;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS,
    DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS, DEFAULT_RATE_SWEEP_INTERVAL,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_USAGE_FLUSH_INTERVAL_MS,
};

// THE INSTALL SIDE lives with the shape it installs, in `busbar_substrate::config::limits`: the
// process-global slot, the build-scoped rollback guard, and the test-only unconditional installer
// with the lock that serializes it. Re-exported here BY IDENTITY at their historical
// `busbar_core::limits::` paths — same statics, same guard type, same lock — so this crate's
// composition root, its accessors below and its tests are untouched, and a plane crate's tests
// install the same posture against the same slot without naming this crate.
pub use busbar_substrate::config::limits::InstallGuard;
#[cfg(any(test, feature = "test-support"))]
pub use busbar_substrate::config::limits::{install, LIMITS_TEST_LOCK};

/// Read the installed value (or `None` when uninstalled — tests / pre-install).
fn get() -> Option<LimitsResolved> {
    busbar_substrate::config::limits::installed()
}

/// The egress translate-body cap (bytes). COUPLED to ingress `request_body_max_bytes`: one knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap,
/// so a body the gateway accepts inbound is always buffer-translatable on the cross-protocol egress
/// path. When uninstalled, falls back to the historical 32 MiB.
pub fn translate_body_max_bytes() -> usize {
    get()
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(DEFAULT_REQUEST_BODY_MAX_BYTES)
}

/// TLS handshake wall-clock bound (seconds), read per accepted connection in `tls::serve_one`.
pub(crate) fn tls_handshake_timeout_secs() -> u64 {
    get()
        .map(|l| l.tls_handshake_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS)
}

/// Inbound request-BODY inter-frame read bound (seconds), read per served connection in `tls`. Bounds
/// a slow-loris that dribbles the request body after headers are complete.
pub(crate) fn request_body_read_timeout_secs() -> u64 {
    get()
        .map(|l| l.request_body_read_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS)
}

/// Cap on a buffered upstream ERROR / verbatim-relay body (bytes).
pub(crate) fn upstream_error_body_max_bytes() -> usize {
    get()
        .map(|l| l.upstream_error_body_max_bytes)
        // No standalone const re-export needed: the resolved value always carries the default.
        .unwrap_or(crate::config::DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES)
}

// 1.5.3: there is deliberately NO process-global webhook-delivery-CONCURRENCY accessor
// here either. Each NAMED `export:` webhook instance owns its `settings.max_inflight_deliveries` and
// its own `AdmissionGate` (`export::webhook::Target::gate`), so one saturated sink can never consume
// the budget an operator capped on another. `LimitsResolved::max_inflight_webhook_deliveries` (the
// MAX across instances) survives only as the bound `config_validate` range-checks.

// 1.5.3: there is deliberately NO process-global webhook-delivery-timeout accessor here. `export:`
// carries NAMED webhook instances, each with its own `settings.delivery_timeout_secs`, so the
// deadline is read PER TARGET at the delivery site (`export::webhook::Target::timeout`). A global
// accessor would have to pick one instance's value and silently apply it to the others.

/// Max per-key gauge series emitted per `/metrics` scrape.
pub(crate) fn key_gauge_limit() -> usize {
    get()
        .map(|l| l.key_gauge_limit)
        .unwrap_or(DEFAULT_KEY_GAUGE_LIMIT)
}

/// Rate-limiter stale-entry sweep amortization interval.
pub(crate) fn rate_sweep_interval() -> u32 {
    get()
        .map(|l| l.rate_sweep_interval)
        .unwrap_or(DEFAULT_RATE_SWEEP_INTERVAL)
}

/// Write-behind flush cadence (ms) for the in-memory governance usage/budget counters. On an
/// UNGRACEFUL crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be
/// lost; a graceful shutdown flushes fully (the flusher's shutdown arm). Default 100.
pub(crate) fn usage_flush_interval_ms() -> u64 {
    get()
        .map(|l| l.usage_flush_interval_ms)
        .unwrap_or(DEFAULT_USAGE_FLUSH_INTERVAL_MS)
}

/// Process-wide active-probe interval fallback (seconds). Per-lane `health.interval_secs` overrides.
pub fn default_probe_interval_secs() -> u64 {
    get()
        .map(|l| l.default_probe_interval_secs)
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
}

/// Process-wide active-probe timeout fallback (seconds). Per-lane `health.timeout_secs` overrides.
pub fn default_probe_timeout_secs() -> u64 {
    get()
        .map(|l| l.default_probe_timeout_secs)
        .unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS)
}

/// Global default routing-policy timeout (ms). Per-policy `policy.timeout_ms` overrides.
pub(crate) fn default_policy_timeout_ms() -> u64 {
    get()
        .map(|l| l.default_policy_timeout_ms)
        .unwrap_or(DEFAULT_POLICY_TIMEOUT_MS)
}

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod tests;
