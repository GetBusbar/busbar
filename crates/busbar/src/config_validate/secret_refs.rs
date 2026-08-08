// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE secret-reference walk: enumerate EVERY [`SecretRef`] in a resolved [`RootCfg`], as
//! `(config path, &SecretRef)`.
//!
//! # Why this file exists, and why it is written the way it is
//!
//! This is the list `--validate` walks in `main::validate_builtin_secrets_resolve` (the 1.5.3
//! breaking change: an unresolvable credential makes `--validate` exit 1 instead of printing
//! `ok: config valid`), and the list `main::validate_secret_refs` walks for registry-backed module
//! existence. Both answers are only as complete as this walk.
//!
//! It used to be a HAND-WRITTEN list of ~8 field accesses. Nothing tied it to the type definitions,
//! so adding a secret-bearing field to config produced NO compile error and NO test failure - the
//! new credential was silently skipped and `--validate` reported a config valid whose credential
//! cannot resolve. It FAILED OPEN, which is the wrong direction for a credential.
//!
//! And it was not hypothetical: `identity-providers.<name>.browser_login.client_secret` - a real
//! `SecretRef` the core resolves at hosted-login build time and injects into the OAuth
//! token-exchange hop (`auth::token`) - was MISSING from that list for its whole life.
//!
//! ## The mechanism: exhaustive destructure, no `..`, anywhere
//!
//! Every function below opens with a `let Type { field, field, .. }` - WITHOUT the `..`. Rust makes
//! a non-exhaustive struct pattern a compile ERROR (E0027), so adding a field to any type reachable
//! from `RootCfg` breaks the build HERE and forces a decision: is it a secret, or is it not?
//! A field that is not a secret is bound to a `_`-prefixed name, which is the decision recorded in
//! code. There is no way to add a field and have it silently skipped.
//!
//! Field-less enums are matched exhaustively too (E0004 on a new variant) where a variant could
//! plausibly ever carry data.
//!
//! ## WHERE THE COVERAGE ENDS - stated precisely, not hand-waved
//!
//! The destructure is COMPLETE over `RootCfg` and every struct reachable from it. Three gaps
//! remain, and each is a property of the config grammar, not of this walk:
//!
//! 1. **Opaque `settings:` bags** (`serde_json::Map<String, Value>` on `StoreCfg`,
//!    `SecretModuleCfg`, `HookCfg`, `AuthChainEntry`, `AuthMethodCfg`, `IdentityProviderCfg`,
//!    `ExportDefCfg`). A plugin's own settings may carry a `SecretRef`-SHAPED value
//!    (`{ token: { env: VAULT_TOKEN } }`) - `config::secret::SettingValue::Reference` resolves those.
//!    They are DYNAMIC (no Rust type names them) so no destructure can reach them, and they are
//!    resolved on a different path (`resolve_settings` at module-open time, fail-closed there).
//!    A type-level walk cannot cover a type-less surface; this is the honest boundary.
//! 2. **`export.request_log_webhooks[].auth_header.value`** is a `String`, not a `SecretRef` - a
//!    plaintext credential in the config grammar. Retyping it is a BREAKING grammar change and is
//!    therefore out of scope for a fix release; it is named here so it is tracked, not forgotten.
//! 3. **`RootCfg` is the RESOLVED config.** The on-disk `DeployCfg` twin (`ProviderDeploy.api_key`,
//!    `AuthDeployCfg.signing_key`) is not walked, because everything it carries is projected into
//!    `RootCfg` by `config::resolve` before any validation runs. If a future `DeployCfg` secret is
//!    ever DROPPED by `resolve` instead of projected, this walk would not see it - but a dropped
//!    secret is inert, so it cannot produce the fail-open this file exists to prevent.

use crate::config::groups::{ChildDefault, GroupCfg, LimitCfg};
use crate::config::{
    AffinityCfg, AuthCfg, AuthChainEntry, AuthMethodCfg, BreakerCfg, BreakerTripConfig,
    BrowserLoginCfg, ExportAuthHeader, ExportCfg, ExportDefCfg, FailoverCfg, FileSettings,
    HealthCfg, HookCfg, IdentityProviderCfg, LimitsResolved, ModelCfg, OtlpSettings, PoolCfg,
    PoolMember, PrometheusSettings, ProviderCfg, RateEntryCfg, ReasoningEffortBudgets, RootCfg,
    SecretModuleCfg, SecretRef, StoreCfg, TlsCfg, WebhookSettings,
};

/// The accumulator every walker pushes into: `(human-readable config path, the reference)`.
type Refs<'a> = Vec<(String, &'a SecretRef)>;

/// Enumerate EVERY secret reference in the resolved config as `(what, &SecretRef)`, where `what` is
/// the human-readable config path used in error messages. The SINGLE source of truth for which
/// references are secrets: the structural check in `validate_secret_refs_structural` and the
/// registry-backed module-existence check in `main::validate_secret_refs` (deferred until the plugin
/// registry exists) both walk this list, so a new secret-bearing field is covered by both the moment
/// the compiler forces it to be handled here.
///
/// DETERMINISTIC ORDER: `providers:` / `pools:` / `models:` / `hooks:` are `HashMap`s, whose
/// iteration order varies per process. `--validate` reports the FIRST unresolvable reference, so an
/// unsorted walk would report a DIFFERENT field on each run for a config with two bad secrets. Every
/// map is walked in sorted-key order.
pub(crate) fn secret_refs(cfg: &RootCfg) -> Refs<'_> {
    let mut out: Refs<'_> = Vec::new();

    // EXHAUSTIVE, NO `..`. Adding a field to `RootCfg` is a compile error here.
    let RootCfg {
        // -- secret-bearing (walked) --------------------------------------------------------------
        providers,
        tls,
        admin_tls,
        auth,
        identity_providers,
        // -- walked for completeness: no `SecretRef` today, but each is an operator-config struct a
        //    credential could plausibly be added to, so the destructure continues into them. ------
        pools,
        models,
        hooks,
        groups,
        store,
        secrets,
        export,
        export_defs,
        rate_card,
        limits,
        // -- NOT secret-bearing: scalars and lists of scalars. Bound (not `..`-skipped) so that
        //    RETYPING any of them to a `SecretRef` is a compile error, not a silent omission. -----
        listen: _listen,
        public_url: _public_url,
        admin_listen: _admin_listen,
        upstream_credentials: _upstream_credentials,
        admin_auth: _admin_auth,
        per_request_fee: _per_request_fee,
        global_hooks: _global_hooks,
        blocked_metadata_hosts: _blocked_metadata_hosts,
        allow_metadata_hosts: _allow_metadata_hosts,
        allow_all_metadata: _allow_all_metadata,
    } = cfg;

    let mut provider_names: Vec<&String> = providers.keys().collect();
    provider_names.sort();
    for name in provider_names {
        walk_provider(&format!("providers.{name}"), &providers[name], &mut out);
    }
    if let Some(t) = tls {
        walk_tls("tls", t, &mut out);
    }
    if let Some(t) = admin_tls {
        walk_tls("admin_tls", t, &mut out);
    }
    if let Some(a) = auth {
        walk_auth("auth", a, &mut out);
    }
    for (name, ip) in identity_providers {
        walk_identity_provider(&format!("identity-providers.{name}"), ip, &mut out);
    }

    let mut pool_names: Vec<&String> = pools.keys().collect();
    pool_names.sort();
    for name in pool_names {
        walk_pool(&pools[name]);
    }
    let mut model_names: Vec<&String> = models.keys().collect();
    model_names.sort();
    for name in model_names {
        walk_model(&models[name]);
    }
    let mut hook_names: Vec<&String> = hooks.keys().collect();
    hook_names.sort();
    for name in hook_names {
        walk_hook(&hooks[name]);
    }
    for g in groups.values() {
        walk_group(g);
    }
    if let Some(s) = store {
        walk_store(s);
    }
    for s in secrets.values() {
        walk_secret_module(s);
    }
    walk_export(export);
    for d in export_defs.values() {
        walk_export_def(d);
    }
    if let Some(card) = rate_card {
        for e in card.values() {
            walk_rate_entry(e);
        }
    }
    walk_limits(limits);

    out
}

// -- Secret-BEARING types: every one pushes into `out`. --------------------------------------------

fn walk_tls<'a>(at: &str, tls: &'a TlsCfg, out: &mut Refs<'a>) {
    let TlsCfg {
        cert,
        key,
        client_ca,
    } = tls;
    out.push((format!("{at}.cert"), cert));
    out.push((format!("{at}.key"), key));
    if let Some(ca) = client_ca {
        out.push((format!("{at}.client_ca"), ca));
    }
}

fn walk_provider<'a>(at: &str, p: &'a ProviderCfg, out: &mut Refs<'a>) {
    let ProviderCfg {
        api_key,
        health,
        protocol: _protocol,
        base_url: _base_url,
        error_map: _error_map,
        path: _path,
        path_base: _path_base,
        token_url: _token_url,
        scope: _scope,
        subject: _subject,
        // `ProviderAuth` selects an auth STYLE (bearer / api-key / ...); it carries no credential.
        auth: _auth,
        allow_metadata_hosts: _allow_metadata_hosts,
    } = p;
    out.push((format!("{at}.api_key"), api_key));
    if let Some(h) = health {
        walk_health(h);
    }
}

fn walk_auth<'a>(at: &str, a: &'a AuthCfg, out: &mut Refs<'a>) {
    let AuthCfg {
        signing_key,
        chain,
        admin_auth,
        methods,
        role_bindings: _role_bindings,
        key_ttl: _key_ttl,
    } = a;
    if let Some(sk) = signing_key {
        out.push((format!("{at}.signing_key"), sk));
    }
    // LEGACY LABEL, PRESERVED DELIBERATELY: the pre-1.5.4 walk emitted exactly one admin-token
    // entry under this name, and operator-facing error text is a compatibility surface. Every OTHER
    // chain entry's token gets a per-entry path so two providers can never collide in one message.
    for e in admin_auth {
        let at = if e.module == crate::config::ADMIN_TOKENS_MODULE {
            format!("{at}.admin_auth admin-tokens token")
        } else {
            format!("{at}.admin_auth[{}]", e.name)
        };
        walk_chain_entry(&at, e, out);
    }
    for e in chain {
        walk_chain_entry(&format!("{at}.chain[{}]", e.name), e, out);
    }
    for (name, m) in methods {
        walk_auth_method(&format!("{at}.methods.{name}"), m, out);
    }
}

fn walk_chain_entry<'a>(at: &str, e: &'a AuthChainEntry, out: &mut Refs<'a>) {
    let AuthChainEntry {
        token,
        name: _name,
        module: _module,
        max_admin_scope: _max_admin_scope,
        // Opaque plugin settings - see the module header, gap 1.
        settings: _settings,
    } = e;
    if let Some(t) = token {
        // `at` already carries the legacy `... admin-tokens token` suffix for the built-in case.
        let label = if at.ends_with("token") {
            at.to_string()
        } else {
            format!("{at}.token")
        };
        out.push((label, t));
    }
}

fn walk_auth_method<'a>(at: &str, m: &'a AuthMethodCfg, out: &mut Refs<'a>) {
    let AuthMethodCfg {
        browser_login,
        module: _module,
        settings: _settings,
    } = m;
    if let Some(bl) = browser_login {
        walk_browser_login(at, bl, out);
    }
}

fn walk_identity_provider<'a>(at: &str, ip: &'a IdentityProviderCfg, out: &mut Refs<'a>) {
    let IdentityProviderCfg {
        token,
        browser_login,
        module: _module,
        max_admin_scope: _max_admin_scope,
        settings: _settings,
    } = ip;
    if let Some(t) = token {
        out.push((format!("{at}.token"), t));
    }
    if let Some(bl) = browser_login {
        walk_browser_login(at, bl, out);
    }
}

/// THE FIELD THE HAND-WRITTEN LIST MISSED. `browser_login.client_secret` is resolved by
/// `auth::token` when the hosted-login page is built and injected verbatim into the OAuth
/// token-exchange hop; an unresolvable one is a login that fails at first use.
fn walk_browser_login<'a>(at: &str, bl: &'a BrowserLoginCfg, out: &mut Refs<'a>) {
    let BrowserLoginCfg {
        client_secret,
        client_id: _client_id,
    } = bl;
    if let Some(cs) = client_secret {
        out.push((format!("{at}.browser_login.client_secret"), cs));
    }
}

// -- NOT secret-bearing today. --------------------------------------------------------------------
//
// Each of these exists ONLY to make the destructure total: they take no `out`, push nothing, and
// their whole body is the exhaustive `let` that fails to compile when a field is added. That is the
// point - a new `SecretRef` field on any of them stops the build and lands the author on the
// module header above, which tells them what to do.
//
// `#[allow(clippy::needless_pass_by_value)]` is deliberately NOT used: everything is by reference so
// the checks are free at every call site.

fn walk_health(h: &HealthCfg) {
    let HealthCfg {
        mode: _mode,
        interval_secs: _interval_secs,
        timeout_secs: _timeout_secs,
    } = h;
}

fn walk_model(m: &ModelCfg) {
    let ModelCfg {
        max_requests: _max_requests,
        provider: _provider,
        max_concurrent: _max_concurrent,
        default_max_tokens: _default_max_tokens,
        upstream_model: _upstream_model,
        attempt_timeout_ms: _attempt_timeout_ms,
        reasoning: _reasoning,
        prompt_caching: _prompt_caching,
    } = m;
}

fn walk_pool(p: &PoolCfg) {
    let PoolCfg {
        members,
        breaker,
        failover,
        affinity,
        upstream_credentials: _upstream_credentials,
        on_exhausted: _on_exhausted,
        policy: _policy,
        gates: _gates,
        base_named: _base_named,
    } = p;
    for m in members {
        walk_pool_member(m);
    }
    if let Some(b) = breaker {
        walk_breaker(b);
    }
    if let Some(f) = failover {
        walk_failover(f);
    }
    if let Some(a) = affinity {
        walk_affinity(a);
    }
}

fn walk_pool_member(m: &PoolMember) {
    let PoolMember {
        model: _model,
        weight: _weight,
        context_max: _context_max,
        tier: _tier,
        attempt_timeout_ms: _attempt_timeout_ms,
        reasoning: _reasoning,
        tags: _tags,
    } = m;
}

fn walk_breaker(b: &BreakerCfg) {
    let BreakerCfg {
        base_cooldown_secs: _base_cooldown_secs,
        max_cooldown_secs: _max_cooldown_secs,
        trip,
    } = b;
    if let Some(t) = trip {
        let BreakerTripConfig {
            mode: _mode,
            window_secs: _window_secs,
            threshold: _threshold,
            min_requests: _min_requests,
            consecutive_n: _consecutive_n,
        } = t;
    }
}

fn walk_failover(f: &FailoverCfg) {
    let FailoverCfg {
        timeout_secs: _timeout_secs,
        exclusions: _exclusions,
        max_hops: _max_hops,
    } = f;
}

fn walk_affinity(a: &AffinityCfg) {
    let AffinityCfg {
        mode: _mode,
        header_name: _header_name,
    } = a;
}

fn walk_hook(h: &HookCfg) {
    let HookCfg {
        kind: _kind,
        plugin: _plugin,
        timeout_ms: _timeout_ms,
        on_error: _on_error,
        prompt: _prompt,
        user: _user,
        priority: _priority,
        at: _at,
        on_empty: _on_empty,
        // Opaque plugin settings - see the module header, gap 1.
        settings: _settings,
        signals: _signals,
        global: _global,
        default: _default,
        groups: _groups,
        phase: _phase,
    } = h;
}

fn walk_group(g: &GroupCfg) {
    let GroupCfg {
        parent: _parent,
        enabled: _enabled,
        limits,
        child_default,
    } = g;
    for l in limits {
        walk_limit(l);
    }
    if let Some(cd) = child_default {
        let ChildDefault { limits } = cd;
        for l in limits {
            walk_limit(l);
        }
    }
}

fn walk_limit(l: &LimitCfg) {
    let LimitCfg {
        metric: _metric,
        amount: _amount,
        per: _per,
        scope: _scope,
        on_exhaust: _on_exhaust,
        downgrade_to: _downgrade_to,
    } = l;
}

fn walk_store(s: &StoreCfg) {
    let StoreCfg {
        module: _module,
        // Opaque plugin settings - see the module header, gap 1.
        settings: _settings,
    } = s;
}

fn walk_secret_module(s: &SecretModuleCfg) {
    let SecretModuleCfg {
        // Opaque plugin settings - see the module header, gap 1.
        settings: _settings,
    } = s;
}

fn walk_export(e: &ExportCfg) {
    let ExportCfg {
        prometheus,
        request_log_webhooks,
        request_log_files,
        otlp,
    } = e;
    if let Some(p) = prometheus {
        let PrometheusSettings {
            buffer_seconds: _buffer_seconds,
            key_gauge_limit: _key_gauge_limit,
            projection: _projection,
        } = p;
    }
    for w in request_log_webhooks {
        let WebhookSettings {
            url: _url,
            auth_header,
            max_inflight_deliveries: _max_inflight_deliveries,
            delivery_timeout_secs: _delivery_timeout_secs,
            projection: _projection,
        } = w;
        if let Some(h) = auth_header {
            // See the module header, gap 2: `value` is a plaintext `String`, NOT a `SecretRef`.
            // Retyping it is a BREAKING config-grammar change, so it is tracked, not silently fixed.
            let ExportAuthHeader {
                name: _name,
                value: _value,
            } = h;
        }
    }
    for f in request_log_files {
        let FileSettings {
            path: _path,
            rotate_mb: _rotate_mb,
            projection: _projection,
        } = f;
    }
    if let Some(o) = otlp {
        let OtlpSettings {
            url: _url,
            projection: _projection,
        } = o;
    }
}

fn walk_export_def(d: &ExportDefCfg) {
    let ExportDefCfg {
        module: _module,
        streams: _streams,
        fields: _fields,
        durable: _durable,
        // Opaque plugin settings - see the module header, gap 1.
        settings: _settings,
    } = d;
}

fn walk_rate_entry(r: &RateEntryCfg) {
    let RateEntryCfg {
        input_utok: _input_utok,
        output_utok: _output_utok,
        cache_read_utok: _cache_read_utok,
        cache_write_utok: _cache_write_utok,
    } = r;
}

fn walk_limits(l: &LimitsResolved) {
    let LimitsResolved {
        upstream_request_timeout_secs: _a,
        request_body_max_bytes: _b,
        pool_max_idle_per_host: _c,
        pool_idle_timeout_secs: _d,
        max_inbound_concurrent: _e,
        max_keys_per_principal: _f,
        max_auto_provisioned_groups: _g,
        hard_down_cooldown_secs: _h,
        upstream_error_body_max_bytes: _i,
        tls_handshake_timeout_secs: _j,
        request_body_read_timeout_secs: _k,
        max_honored_retry_after_secs: _l,
        default_max_tokens: _m,
        reasoning_effort_budgets: budgets,
        max_inflight_webhook_deliveries: _n,
        key_gauge_limit: _o,
        rate_sweep_interval: _p,
        usage_flush_interval_ms: _q,
        upstream_http1_only: _r,
        upstream_h2_prior_knowledge: _s,
        default_probe_interval_secs: _t,
        default_probe_timeout_secs: _u,
        default_policy_timeout_ms: _v,
    } = l;
    let ReasoningEffortBudgets {
        minimal: _minimal,
        low: _low,
        medium: _medium,
        high: _high,
    } = budgets;
}
