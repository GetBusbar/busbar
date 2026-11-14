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
pub const DEFAULT_ACCOUNT: Limit = Limit {
    max: 3,
    window_secs: 15 * 60,
};
/// Per source: 20 per 15 minutes per address or /64.
pub const DEFAULT_SOURCE: Limit = Limit {
    max: 20,
    window_secs: 15 * 60,
};
/// The /48 aggregate.
pub const DEFAULT_AGGREGATE_48: u32 = 100;
/// The /32 aggregate.
pub const DEFAULT_AGGREGATE_32: u32 = 500;
/// Submissions per minute per source.
pub const DEFAULT_SUBMISSIONS_PER_MINUTE: u32 = 30;
/// The global alarm threshold.
pub const DEFAULT_GLOBAL_PER_MINUTE: u32 = 600;
/// The admin door.
pub const DEFAULT_ADMIN: Limit = Limit {
    max: 50,
    window_secs: 5 * 60,
};

/// The `Retry-After` bounds of a throttled sign-in, seconds.
pub const RETRY_AFTER_MIN_SECS: u64 = 60;
/// See [`RETRY_AFTER_MIN_SECS`].
pub const RETRY_AFTER_MAX_SECS: u64 = 900;

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

/// The shortest window any login limit takes.
pub const WINDOW_MIN_SECS: u64 = 60;
/// The longest.
pub const WINDOW_MAX_SECS: u64 = 24 * 60 * 60;
/// The highest per-account ceiling (NIST 800-63B §5.2.2: no more than 100).
pub const ACCOUNT_MAX: u32 = 100;

/// A BUSBAR-3133 config refusal, rendered as the operator-error-codes registry renders a `text`
/// entry (`BUSBAR-NNNN: <text>. See <link>`); the registry's generated constructor replaces this
/// when that line lands on dev.
#[must_use]
pub fn invalid(detail: &str) -> String {
    let code = crate::diagnostics::CONFIG_LOGIN_LIMITS_INVALID.banner();
    format!("{code}: {detail}. See https://getbusbar.com/docs/1.6/errors/{code}")
}

fn window(key: &str, raw: Option<&String>, default: u64, errors: &mut Vec<String>) -> u64 {
    let Some(raw) = raw else {
        return default;
    };
    match busbar_contract::duration::parse_duration_secs(raw) {
        Ok(secs) if (WINDOW_MIN_SECS..=WINDOW_MAX_SECS).contains(&secs) => secs,
        Ok(_) => {
            errors.push(invalid(&format!("{key}: `{raw}` is outside 1m..=24h")));
            default
        }
        Err(e) => {
            errors.push(invalid(&format!("{key}: `{raw}` is not a duration ({e})")));
            default
        }
    }
}

fn count(key: &str, raw: Option<u32>, default: u32, max: u32, errors: &mut Vec<String>) -> u32 {
    match raw {
        None => default,
        Some(n) if (1..=max).contains(&n) => n,
        Some(n) => {
            errors.push(invalid(&format!("{key}: {n} is outside 1..={max}")));
            default
        }
    }
}

/// Resolve `auth.login_limits`, the providers' `browser_login` overrides and the `advanced`
/// client-address keys; every refusal is a BUSBAR-3133 line.
pub fn resolve(
    cfg: Option<&crate::config::LoginLimitsCfg>,
    providers: &crate::config::IdentityProviders,
    advanced: &crate::config::AdvancedCfg,
) -> Result<LoginLimitsPolicy, Vec<String>> {
    let default_cfg = crate::config::LoginLimitsCfg::default();
    let cfg = cfg.unwrap_or(&default_cfg);
    let mut errors = Vec::new();
    let d = LoginLimitsPolicy::default();
    let account = Limit {
        max: count(
            "auth.login_limits.per_account.max_failures",
            cfg.per_account.max_failures,
            d.account.max,
            ACCOUNT_MAX,
            &mut errors,
        ),
        window_secs: window(
            "auth.login_limits.per_account.window",
            cfg.per_account.window.as_ref(),
            d.account.window_secs,
            &mut errors,
        ),
    };
    let source = SourcePolicy {
        enabled: cfg.per_source.enabled.unwrap_or(true),
        failures: Limit {
            max: count(
                "auth.login_limits.per_source.max_failures",
                cfg.per_source.max_failures,
                d.source.failures.max,
                u32::MAX,
                &mut errors,
            ),
            window_secs: window(
                "auth.login_limits.per_source.window",
                cfg.per_source.window.as_ref(),
                d.source.failures.window_secs,
                &mut errors,
            ),
        },
        submissions_per_minute: count(
            "auth.login_limits.per_source.max_submissions_per_minute",
            cfg.per_source.max_submissions_per_minute,
            d.source.submissions_per_minute,
            u32::MAX,
            &mut errors,
        ),
        ..d.source
    };
    if source.enabled && account.max > source.failures.max {
        errors.push(invalid(&format!(
            "auth.login_limits.per_account.max_failures ({}) exceeds \
             auth.login_limits.per_source.max_failures ({})",
            account.max, source.failures.max
        )));
    }
    let global = GlobalPolicy {
        enabled: cfg.global.enabled.unwrap_or(true),
        failures_per_minute: count(
            "auth.login_limits.global.max_failures_per_minute",
            cfg.global.max_failures_per_minute,
            d.global.failures_per_minute,
            u32::MAX,
            &mut errors,
        ),
    };
    let admin = Limit {
        max: count(
            "auth.login_limits.admin.max_failures",
            cfg.admin.max_failures,
            d.admin.max,
            u32::MAX,
            &mut errors,
        ),
        window_secs: window(
            "auth.login_limits.admin.window",
            cfg.admin.window.as_ref(),
            d.admin.window_secs,
            &mut errors,
        ),
    };
    let mut per_method = BTreeMap::new();
    for (name, def) in providers {
        let Some(bl) = def.browser_login.as_ref() else {
            continue;
        };
        if bl.max_failures.is_none() && bl.failure_window.is_none() {
            continue;
        }
        let at = format!("identity-providers.{name}.browser_login");
        per_method.insert(
            name.clone(),
            Limit {
                max: count(
                    &format!("{at}.max_failures"),
                    bl.max_failures,
                    account.max,
                    ACCOUNT_MAX,
                    &mut errors,
                ),
                window_secs: window(
                    &format!("{at}.failure_window"),
                    bl.failure_window.as_ref(),
                    account.window_secs,
                    &mut errors,
                ),
            },
        );
    }
    let proxies = TrustedProxies::read(
        &advanced.trusted_proxies,
        advanced.forwarded_header.as_deref(),
    )
    .unwrap_or_else(|e| {
        errors.push(invalid(&e));
        TrustedProxies::default()
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(LoginLimitsPolicy {
        account,
        per_method,
        source,
        global,
        admin,
        proxies,
    })
}
