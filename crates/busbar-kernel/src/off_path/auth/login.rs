// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for `auth::login` and `auth::login_limits`: the hosted-login map's build (boot
//! and reload), its configuration refusals, and the login limiter's policy and trusted-proxy parsing.

use indexmap::IndexMap;

use crate::auth::login::LoginMethods;
use crate::config::AuthCfg;

fn login_module_refusal(name: &str, module: &str, reason: &str) -> String {
    format!(
        "identity-providers.{name} (module '{module}') could not be loaded as a `kind: auth` login plugin: {reason}"
    )
}

pub(crate) fn missing_login_axis(name: &str, module: &str) -> String {
    let reason = format!("no `kind: auth` plugin answers to '{module}'");
    login_module_refusal(name, module, &reason)
}

impl LoginMethods {
    /// The hosted login methods: every method's module is refused once its settings resolve (no
    /// `kind: auth` plugin answers it), so a build with methods refuses and one without has none.
    pub(crate) fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        if let Some((name, mc)) = cfg.methods.iter().next() {
            crate::auth::instances::provider_settings(
                cfg,
                name,
                &mc.module,
                &mc.settings,
                registry,
                secret_resolver,
                |e| format!("identity-providers.{name} settings: {e}"),
            )?;
            return Err(missing_login_axis(name, &mc.module));
        }
        Ok(Self {
            methods: IndexMap::new(),
        })
    }
}

// ---- the login limiter's configuration (`auth.login_limits`, `advanced` client-address keys) ----

use std::collections::BTreeMap;

use crate::auth::login_limits::policy::{GlobalPolicy, Limit, LoginLimitsPolicy, SourcePolicy};
use crate::auth::login_limits::source::{ForwardedHeader, TrustedProxies};
use busbar_contract::net::IpNet;

/// The shortest window any login limit takes.
const WINDOW_MIN_SECS: u64 = 60;
/// The longest.
const WINDOW_MAX_SECS: u64 = 24 * 60 * 60;
/// The highest per-account ceiling (NIST 800-63B §5.2.2: no more than 100).
const ACCOUNT_MAX: u32 = 100;

/// A BUSBAR-3133 config refusal, rendered as the operator-error-codes registry renders a `text`
/// entry (`BUSBAR-NNNN: <text>. See <link>`); the registry's generated constructor replaces this
/// when that line lands on dev.
fn invalid(detail: &str) -> String {
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
pub(crate) fn resolve(
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

impl TrustedProxies {
    /// Read the configured entries; the error names the first bad one.
    pub fn read(entries: &[String], header: Option<&str>) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            match IpNet::parse(entry) {
                Ok(net) => nets.push(net),
                Err(busbar_contract::net::IpNetError::HostBitsSet) => {
                    return Err(format!(
                    "advanced.trusted_proxies[{i}]: `{entry}` sets address bits past its prefix \
                         length; write the network address"
                ))
                }
                Err(busbar_contract::net::IpNetError::NotNetwork) => {
                    return Err(format!(
                        "advanced.trusted_proxies[{i}]: `{entry}` is not an IP address or a CIDR"
                    ))
                }
            }
        }
        let header = match header {
            None => ForwardedHeader::default(),
            Some(name) => ForwardedHeader::parse(name).ok_or_else(|| {
                format!(
                    "advanced.forwarded_header: `{name}` is not `x-forwarded-for` or `forwarded`"
                )
            })?,
        };
        Ok(Self { nets, header })
    }
}
