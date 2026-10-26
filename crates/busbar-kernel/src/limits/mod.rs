// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Process-wide operational limits ("NEVER CODED CAPS"), published from the resolved config
//! (`config::LimitsResolved`) when a generation goes live — the boot generation's commit and every
//! subsequent swap (`config::limits::publish`) — and read by the use sites that live too deep in a call
//! stack to thread `App`/`&self` through. A configuration build reads its own candidate's values
//! through a build-scoped view no other thread sees (`config::limits::BuildScope`).
//!
//! Each accessor returns the published value, and otherwise the HISTORICAL hardcoded default (the
//! same `config::DEFAULT_*` const the serde defaults use), so a unit test that publishes nothing
//! sees byte-for-byte the default behaviour. Publishing again replaces the values.
//!
//! Values threaded explicitly (the upstream client timeout/pool-idle, the axum `DefaultBodyLimit`,
//! the inbound concurrency layer, the TLS handshake bound, and the store's hard-down /
//! retry-after ceiling) do NOT live here — they reach their site directly from `RootCfg.limits`.
//! This module is only for the sites without such a path.

pub(crate) mod admission;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS, DEFAULT_RATE_SWEEP_INTERVAL,
};
// The body-cap default is no longer read by any accessor on this page (the translate cap moved to
// its own home); the tests below still assert the uninstalled fallback against it.
#[cfg(test)]
use crate::config::DEFAULT_REQUEST_BODY_MAX_BYTES;

// THE PUBLISH SIDE lives with the shape it publishes, in `busbar_kernel::config::limits`: the
// process-global slot, the build scope, the publication, and the test-only installers with the
// lock that serializes them. The test guard is re-exported here for this module's own tests.
#[cfg(test)]
pub(crate) use busbar_kernel::config::limits::InstallGuard;
// `install` is dropped: nothing in the workspace names `busbar_kernel::limits::install` -- every real
// caller spells `busbar_kernel::config::limits::install`, its home. `LIMITS_TEST_LOCK` stays,
// `pub(crate)`, for this crate's own serialized limit tests.
#[cfg(test)]
pub(crate) use busbar_kernel::config::limits::LIMITS_TEST_LOCK;

/// Read the installed value (or `None` when uninstalled — tests / pre-install).
fn get() -> Option<LimitsResolved> {
    busbar_kernel::config::limits::installed()
}

// THE EGRESS TRANSLATE-BODY CAP is READ AT ITS OWN HOME, not here. It was a `pub fn
// translate_body_max_bytes()` on this page reading `installed().request_body_max_bytes` with a
// 32 MiB uninstalled fallback -- and `busbar_kernel::proxy::max_translate_body_bytes()` is the
// same number, mirrored out of the same slot by `mirror_derived_caps` on EVERY mutation (install,
// reload, `InstallGuard` rollback, the raw `set_installed` poke) with the same fallback constant,
// `TRANSLATE_BODY_MAX_BYTES_DEFAULT`. The codec crates already read it there. Two names for one
// process-global is one name too many while this crate is being emptied, and this is not a money
// figure or an admission figure -- it is a transport body cap, so its home is the neutral values
// leaf that already owns it, not a unit. This crate's four call sites now name that home.

/// TLS handshake wall-clock bound (seconds), read per accepted connection in
/// `busbar::root::listener`.
pub fn tls_handshake_timeout_secs() -> u64 {
    get()
        .map(|l| l.tls_handshake_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS)
}

/// Inbound request-BODY inter-frame read bound (seconds), read per served connection in
/// `busbar::root::listener`. Bounds a slow-loris that dribbles the request body after headers are
/// complete.
pub fn request_body_read_timeout_secs() -> u64 {
    get()
        .map(|l| l.request_body_read_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS)
}

// The upstream ERROR-body cap has no accessor here: its one reader, proxy_vocab.rs's
// `max_upstream_buffered_bytes`, left with that file, and the cap is read through the process
// global `config::limits::mirror_derived_caps` sets (`busbar_kernel_egress::upstream`).

// There is deliberately NO process-global delivery accessor here for an export sink, for
// concurrency or for the deadline: an export sink is a plugin, and each NAMED instance states its
// own in-flight bound when started and carries its own delivery timeout on each request — so one
// saturated sink can never consume another's budget, and no accessor has to pick one instance's
// value for the others.

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

/// Global default routing-policy timeout (ms). Per-policy `policy.timeout_ms` overrides.
pub(crate) fn default_policy_timeout_ms() -> u64 {
    get()
        .map(|l| l.default_policy_timeout_ms)
        .unwrap_or(DEFAULT_POLICY_TIMEOUT_MS)
}

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod tests;
