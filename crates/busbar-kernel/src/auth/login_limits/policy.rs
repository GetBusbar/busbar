// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESOLVED LIMITS: `auth.login_limits`, the per-provider `browser_login` overrides and the
//! `advanced` client-address keys, validated once per config generation.

use std::collections::BTreeMap;

use super::source::TrustedProxies;

/// One failure ceiling: at most `max` failures per `window_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// The ceiling.
    pub max: u32,
    /// The sliding window, seconds.
    pub window_secs: u64,
}

/// The per-source limits (`auth.login_limits.per_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicy {
    /// `false`: only for sites behind a WAF doing this (BUSBAR-4037 at every boot).
    pub enabled: bool,
    /// Failures per window for one IPv4 address or one IPv6 /64.
    pub failures: Limit,
    /// The IPv6 /48 aggregate's ceiling over the same window.
    pub aggregate_48: u32,
    /// The IPv6 /32 aggregate's ceiling over the same window.
    pub aggregate_32: u32,
    /// Submissions per minute from one source, whatever their outcome.
    pub submissions_per_minute: u32,
}

/// The global alarm (`auth.login_limits.global`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalPolicy {
    /// `false`: no alarm and no tightening (BUSBAR-4037 at every boot).
    pub enabled: bool,
    /// Failures per minute on this node that trip the alarm.
    pub failures_per_minute: u32,
}

/// Everything the limiter reads from config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginLimitsPolicy {
    /// The default per-account ceiling. Cannot be disabled.
    pub account: Limit,
    /// Per-provider overrides of [`Self::account`] (`identity-providers.<n>.browser_login`).
    pub per_method: BTreeMap<String, Limit>,
    /// Per-source limits.
    pub source: SourcePolicy,
    /// The global alarm.
    pub global: GlobalPolicy,
    /// The admin door: presented-and-refused credentials per source.
    pub admin: Limit,
    /// Who may state a client address for another.
    pub proxies: TrustedProxies,
}

/// Owner-signed defaults (design Revision 2, R2.1).
const DEFAULT_ACCOUNT: Limit = Limit {
    max: 3,
    window_secs: 15 * 60,
};
/// Per source: 20 per 15 minutes per address or /64.
const DEFAULT_SOURCE: Limit = Limit {
    max: 20,
    window_secs: 15 * 60,
};
/// The /48 aggregate.
const DEFAULT_AGGREGATE_48: u32 = 100;
/// The /32 aggregate.
const DEFAULT_AGGREGATE_32: u32 = 500;
/// Submissions per minute per source.
const DEFAULT_SUBMISSIONS_PER_MINUTE: u32 = 30;
/// The global alarm threshold.
const DEFAULT_GLOBAL_PER_MINUTE: u32 = 600;
/// The admin door.
const DEFAULT_ADMIN: Limit = Limit {
    max: 50,
    window_secs: 5 * 60,
};

/// The `Retry-After` bounds of a throttled sign-in, seconds.
const RETRY_AFTER_MIN_SECS: u64 = 60;
/// See [`RETRY_AFTER_MIN_SECS`].
const RETRY_AFTER_MAX_SECS: u64 = 900;

impl Default for LoginLimitsPolicy {
    fn default() -> Self {
        Self {
            account: DEFAULT_ACCOUNT,
            per_method: BTreeMap::new(),
            source: SourcePolicy {
                enabled: true,
                failures: DEFAULT_SOURCE,
                aggregate_48: DEFAULT_AGGREGATE_48,
                aggregate_32: DEFAULT_AGGREGATE_32,
                submissions_per_minute: DEFAULT_SUBMISSIONS_PER_MINUTE,
            },
            global: GlobalPolicy {
                enabled: true,
                failures_per_minute: DEFAULT_GLOBAL_PER_MINUTE,
            },
            admin: DEFAULT_ADMIN,
            proxies: TrustedProxies::default(),
        }
    }
}

impl LoginLimitsPolicy {
    /// The per-account ceiling a submission to `method` is judged against.
    #[must_use]
    pub fn account_for(&self, method: &str) -> Limit {
        self.per_method.get(method).copied().unwrap_or(self.account)
    }

    /// The `Retry-After` of EVERY throttled answer for `method`, whichever limiter tripped: its
    /// account window rounded up to whole minutes, within 60..=900. One value per method, so the
    /// answer says neither which limiter tripped nor when anyone else's failures happened.
    #[must_use]
    pub fn retry_after_secs(&self, method: &str) -> u64 {
        let window = self.account_for(method).window_secs;
        window
            .div_ceil(60)
            .saturating_mul(60)
            .clamp(RETRY_AFTER_MIN_SECS, RETRY_AFTER_MAX_SECS)
    }
}

// Resolve `auth.login_limits` (built once per config generation, off the request path).
pub(crate) use crate::off_path::auth::login::resolve;
