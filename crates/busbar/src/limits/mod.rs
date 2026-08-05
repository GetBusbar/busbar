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

use std::sync::RwLock;

pub(crate) mod admission;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS,
    DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS, DEFAULT_RATE_SWEEP_INTERVAL,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_USAGE_FLUSH_INTERVAL_MS,
};

/// The installed limits. `None` until `install` runs; `None` means "use the historical default",
/// which is what the per-accessor fallback returns. An `RwLock` (not `OnceLock`) because the
/// config plane RE-installs on every apply/reload — limit changes take effect live. Accessors take
/// an uncontended read lock (writes happen only on config changes); the values these guard are not
/// per-byte hot (per-request/per-connection reads at most).
static INSTALLED: RwLock<Option<LimitsResolved>> = RwLock::new(None);

/// Install (or RE-install) the resolved limits process-wide: at boot from `main`'s construction
/// path, and again on every config apply/reload — the newest install wins, so operator limit
/// changes are live without restart.
///
/// TEST-ONLY. Production installs through [`InstallGuard`], never through this: a config that is
/// subsequently REJECTED must not leave its limits behind, and an unconditional install is exactly
/// what made that possible. `tls`'s handshake-bound tests moved to `InstallGuard` (it restores the
/// prior value on drop, which a bare install cannot). The remaining consumer is
/// `nonstream_tap_cap_is_read_once_per_decision` (`#[ignore]`d — see its own doc comment), whose
/// SUBJECT is racing the live cap by re-installing it in a hot loop with no rollback between
/// iterations; `InstallGuard` cannot serve that (a guard restores on drop, but the test wants the
/// value to keep flipping mid-run).
#[cfg(test)]
pub(crate) fn install(resolved: &LimitsResolved) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some(resolved.clone());
}

/// INSTALL FOR THE DURATION OF A BUILD, AND ROLL BACK UNLESS THE BUILD SUCCEEDS.
///
/// `build_app_from_config` installs the candidate limits FIRST — it has to, because the build reads
/// them through the deep-call-stack accessors above (the store open, the health-probe fallbacks, the
/// routing policy timeout) — but every step AFTER the install is fallible: semantic validation, the
/// plugin pre-flight, secret-ref resolution, the store open. Before this guard, a rejected apply
/// left the REJECTED config's limits installed process-wide while the old `App` kept serving, and no
/// error path put them back. That broke the surface's central promise that an invalid apply changes
/// nothing, and it did so in the worst direction: the values `validate_limits` exists to reject —
/// e.g. a `request_body_max_bytes` below `REQUEST_BODY_MAX_BYTES_FLOOR` — are precisely the ones
/// that got installed anyway, because the range check runs after the install. A 400-ed
/// `POST /config/apply` could shrink the live SigV4 auth-middleware buffer and the cross-protocol
/// translate buffer under a still-running gateway, 401-ing larger Bedrock requests.
///
/// So: snapshot, install, and restore on drop unless [`InstallGuard::commit`] is called. Rollback on
/// the DROP rather than on each `return Err` is what makes it total — a build step added later
/// cannot forget to unwind, and neither can a `?`.
#[must_use = "an uncommitted InstallGuard rolls the limits back when dropped"]
pub(crate) struct InstallGuard {
    /// What was installed before — `None` when nothing was (boot, or a test process).
    prior: Option<LimitsResolved>,
    committed: bool,
}

impl InstallGuard {
    /// Snapshot the currently-installed limits and install `resolved` in their place.
    pub(crate) fn install(resolved: &LimitsResolved) -> Self {
        let mut slot = INSTALLED.write().unwrap_or_else(|e| e.into_inner());
        let prior = slot.clone();
        *slot = Some(resolved.clone());
        Self {
            prior,
            committed: false,
        }
    }

    /// The build succeeded: KEEP the installed limits.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if !self.committed {
            *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = self.prior.clone();
        }
    }
}

/// Read the installed value (or `None` when uninstalled — tests / pre-install).
fn get() -> Option<LimitsResolved> {
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The egress translate-body cap (bytes). COUPLED to ingress `request_body_max_bytes`: one knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap,
/// so a body the gateway accepts inbound is always buffer-translatable on the cross-protocol egress
/// path. When uninstalled, falls back to the historical 32 MiB.
pub(crate) fn translate_body_max_bytes() -> usize {
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

// 1.5.3 (audit MED-5): there is deliberately NO process-global webhook-delivery-CONCURRENCY accessor
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
pub(crate) fn default_probe_interval_secs() -> u64 {
    get()
        .map(|l| l.default_probe_interval_secs)
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
}

/// Process-wide active-probe timeout fallback (seconds). Per-lane `health.timeout_secs` overrides.
pub(crate) fn default_probe_timeout_secs() -> u64 {
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
