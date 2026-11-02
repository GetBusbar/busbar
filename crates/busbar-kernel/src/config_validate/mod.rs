// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::operator_provider;
use busbar_kernel_identity::operator;
use std::collections::{HashMap, HashSet};

use crate::config::RootCfg;
use crate::diagnostics::{
    diag_warn, CONFIG_AUTH_CHAIN_FULL_SCOPE, CONFIG_OPEN_ADMIN_MINT,
    CONFIG_PASSTHROUGH_UNUSED_APIKEY, CONFIG_POOL_HETEROGENEOUS, CONFIG_RATE_CARD_ALL_ZERO,
};
use crate::plane_driver::registry::plane_decl_for;
use busbar_contract::abi::export::CheckPhase;
use busbar_kernel_ledger::cost::{
    flat_card_present, split_plane_lane, PER_REQUEST, PER_SESSION, PLANE_LANE_SEP,
};

const MAX_AFFINITY_HEADER_NAME_LEN: usize = 64;

const MAX_SEMAPHORE_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;

const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;

const MAX_DURATION_MS: u64 = MAX_DURATION_SECS * 1_000;

pub use busbar_contract::net::{extract_normalized_host, host_is_private_or_loopback, scheme_is};
pub use busbar_kernel_egress::trust::net::ssrf_blocked_host;

#[cfg(test)]
use busbar_contract::net::expand_alternate_ipv4;

pub fn validate(cfg: &RootCfg) -> Result<(), Vec<String>> {
    validate_with_unset(cfg, &[])
}

#[cold]
#[inline(never)]
pub fn validate_with_unset(cfg: &RootCfg, unset_env_vars: &[String]) -> Result<(), Vec<String>> {
    validate_with_plugins(cfg, unset_env_vars, false)
}

pub(super) fn validate_with_plugins(
    cfg: &RootCfg,
    unset_env_vars: &[String],
    plugins_enabled: bool,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    reject_cidr_metadata_entries(
        "security.blocked_metadata_hosts",
        &cfg.blocked_metadata_hosts,
        &mut errors,
    );
    reject_cidr_metadata_entries(
        "security.allow_metadata_hosts",
        &cfg.allow_metadata_hosts,
        &mut errors,
    );

    reject_unmappable_metadata_entries(
        "security.blocked_metadata_hosts",
        &cfg.blocked_metadata_hosts,
        &mut errors,
    );
    reject_unmappable_metadata_entries(
        "security.allow_metadata_hosts",
        &cfg.allow_metadata_hosts,
        &mut errors,
    );

    {
        let b = cfg.limits.reasoning_effort_budgets;
        if b.minimal == 0 || b.low == 0 || b.medium == 0 || b.high == 0 {
            errors.push(format!(
                "limits.reasoning_effort_budgets entries must be > 0 (got {}/{}/{}/{})",
                b.minimal, b.low, b.medium, b.high
            ));
        }
        if !(b.minimal <= b.low && b.low <= b.medium && b.medium <= b.high) {
            errors.push(format!(
                "limits.reasoning_effort_budgets must be ascending (minimal <= low <= medium <= high); got {}/{}/{}/{}",
                b.minimal, b.low, b.medium, b.high
            ));
        }
    }

    warn_refused_provider_destinations(cfg);

    let provider_names: HashSet<&str> = cfg.providers.keys().map(|s| s.as_str()).collect();

    let mut model_protocols: HashMap<&str, &str> = HashMap::new();
    for (model_name, model_cfg) in &cfg.models {
        if let Some(provider_name) = cfg.providers.get(&model_cfg.provider) {
            model_protocols.insert(model_name.as_str(), provider_name.dialect());
        } else {
            errors.push(format!(
                "model '{}' references unknown provider '{}'",
                model_name, model_cfg.provider
            ));
        }

        if model_cfg.default_max_tokens == Some(0) {
            errors.push(format!(
                "model '{}' has default_max_tokens: 0; must be > 0 (or omit it to use the {} fallback)",
                model_name,
                crate::config::limits::DEFAULT_MAX_TOKENS
            ));
        }

        if model_cfg.max_concurrent == Some(0) {
            errors.push(format!(
                "model '{}' has max_concurrent: 0; must be >= 1, or omit it (default = unbounded)",
                model_name
            ));
        }

        if let Some(mc_val) = model_cfg.max_concurrent {
            if mc_val > MAX_SEMAPHORE_PERMITS {
                errors.push(format!(
                    "model '{}' has max_concurrent: {mc_val}; must be <= {MAX_SEMAPHORE_PERMITS} \
                     (tokio::sync::Semaphore's hard permit ceiling — a value above it panics at \
                     build time instead of failing validation), or omit the field to mean unbounded",
                    model_name
                ));
            }
        }

        if model_cfg.max_requests == 0 {
            errors.push(format!(
                "model '{}' has max_requests: 0; a lane with a zero lifetime budget never admits a request — use a positive cap, or omit it (default -1 = unlimited)",
                model_name
            ));
        }

        if model_cfg.attempt_timeout_ms == Some(0) {
            errors.push(format!(
                "model '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to disable the per-attempt cap",
                model_name
            ));
        }

        if let Some(ms) = model_cfg
            .attempt_timeout_ms
            .filter(|ms| *ms > MAX_DURATION_MS)
        {
            errors.push(format!(
                "model '{model_name}' has attempt_timeout_ms: {ms}, above the maximum of \
                 {MAX_DURATION_MS} ms (30 years, the async runtime's own 'never' horizon); a larger \
                 duration overflows the clock arithmetic it feeds — omit it to disable the cap"
            ));
        }

        if let Some(um) = &model_cfg.upstream_model {
            if um.trim().is_empty() {
                errors.push(format!(
                    "model '{}' has an empty upstream_model; set a non-empty provider model id, or omit it to use the config key",
                    model_name
                ));
            }
        }

        if reserved_legacy_admin_name(model_name) {
            errors.push(format!(
                "model name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a model reachable via /{}/v1/messages is unreachable to clients and bypasses per-model governance; rename it",
                model_name, model_name
            ));
        }
        if reserved_admin_name(model_name) {
            errors.push(format!(
                "model name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a model reachable via /{}/v1/messages is unreachable to clients and bypasses per-model governance; rename it",
                model_name, admin_root_segment(), admin_root_segment(), admin_root_segment(), model_name
            ));
        }
    }

    let model_names: HashSet<&str> = cfg.models.keys().map(|s| s.as_str()).collect();

    for pool_name in cfg.pools.keys() {
        if provider_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with provider name '{}'; pools and providers must have distinct names",
                pool_name, pool_name
            ));
        }
        if model_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with model name '{}'; pools and models must have distinct names",
                pool_name, pool_name
            ));
        }

        if reserved_legacy_admin_name(pool_name) {
            errors.push(format!(
                "pool name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it",
                pool_name
            ));
        }
        if reserved_admin_name(pool_name) {
            errors.push(format!(
                "pool name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it",
                pool_name, admin_root_segment(), admin_root_segment(), admin_root_segment()
            ));
        }
    }

    for provider_name in cfg.providers.keys() {
        if reserved_legacy_admin_name(provider_name) {
            errors.push(format!(
                "provider name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a provider reachable via the adhoc /admin/<model> route is unreachable to clients; rename it",
                provider_name
            ));
        }
        if reserved_admin_name(provider_name) {
            errors.push(format!(
                "provider name '{}' is reserved: '{}' is the native-API root (the auth middleware routes /{} and /{}/* to the operator admin surface), so a provider reachable via the adhoc /{}/<model> route is unreachable to clients; rename it",
                provider_name, admin_root_segment(), admin_root_segment(), admin_root_segment(), admin_root_segment()
            ));
        }
    }

    let mut known_protocols: Vec<&str> = crate::plane_driver::dispatch::provider_dialects();
    for decl in crate::plane_driver::registry::plane_decls()
        .iter()
        .filter(|d| d.fallback || cfg.plane_sections.contains(d.config_section))
    {
        if let Some(default_section) = decl.default_section {
            if let Some(dialects) = default_section(decl).known_dialects() {
                for d in dialects.iter().copied() {
                    if !known_protocols.contains(&d) {
                        known_protocols.push(d);
                    }
                }
            }
        }
    }
    validate_providers_with(&known_protocols, cfg, unset_env_vars, &mut errors);

    for (pool_name, pool_cfg) in &cfg.pools {
        let mut member_protocols: HashSet<&str> = HashSet::new();

        if pool_cfg.members.is_empty() {
            errors.push(format!(
                "pool '{}' has no members; a pool with an empty member list is un-routable — every request to it 503s with a misleading 'overloaded' message. Add at least one member, or remove the pool",
                pool_name
            ));
        }

        for member in &pool_cfg.members {
            if member.weight == 0 {
                errors.push(format!(
                    "pool '{}' member '{}' weight must be >= 1 (got 0)",
                    pool_name, member.model
                ));
            }

            if member.attempt_timeout_ms == Some(0) {
                errors.push(format!(
                    "pool '{}' member '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to inherit the model's setting",
                    pool_name, member.model
                ));
            }
            if let Some(ms) = member.attempt_timeout_ms.filter(|ms| *ms > MAX_DURATION_MS) {
                errors.push(format!(
                    "pool '{pool_name}' member '{}' has attempt_timeout_ms: {ms}, above the maximum \
                     of {MAX_DURATION_MS} ms (30 years, the async runtime's own 'never' horizon); a \
                     larger duration overflows the clock arithmetic it feeds",
                    member.model
                ));
            }

            if let Some(&protocol) = model_protocols.get(member.model.as_str()) {
                member_protocols.insert(protocol);
            } else if model_names.contains(member.model.as_str()) {
                errors.push(format!(
                    "pool '{}' member '{}' references model '{}', which is defined but whose provider is unresolvable; fix that model's provider reference (the model's 'references unknown provider' error is reported separately)",
                    pool_name, member.model, member.model
                ));
            } else {
                errors.push(format!(
                    "pool '{}' references unknown model '{}'",
                    pool_name, member.model
                ));
            }
        }

        if member_protocols.len() > 1 {
            let mut protocols: Vec<&str> = member_protocols.iter().copied().collect();
            protocols.sort();
            diag_warn!(
                CONFIG_POOL_HETEROGENEOUS,
                pool = %pool_name,
                protocols = %protocols.join("+"),
                "heterogeneous pool: cross-protocol failover translates via the IR and may not preserve all provider features"
            );
        }

        if let Some(breaker) = &pool_cfg.breaker {
            check_pool_breaker(pool_name, breaker, &mut errors);
        }

        if let Some(failover) = &pool_cfg.failover {
            if failover.timeout_secs == 0 {
                errors.push(format!(
                    "pool '{pool_name}' failover.timeout_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s)"
                ));
            } else if failover.timeout_secs > crate::config::MAX_FAILOVER_DEADLINE_SECS {
                errors.push(format!(
                    "pool '{}' failover.timeout_secs ({}) exceeds the maximum of {} s (24h); a per-request failover budget larger than a day is a fat-finger typo. Lower it to <= {} s",
                    pool_name,
                    failover.timeout_secs,
                    crate::config::MAX_FAILOVER_DEADLINE_SECS,
                    crate::config::MAX_FAILOVER_DEADLINE_SECS
                ));
            }

            if let Some(exclusions) = &failover.exclusions {
                let member_targets: HashSet<&str> =
                    pool_cfg.members.iter().map(|m| m.model.as_str()).collect();
                for excluded in exclusions {
                    if !member_targets.contains(excluded.as_str()) {
                        errors.push(format!(
                            "pool '{pool_name}' failover.exclusions references '{excluded}', which is not a member of the pool; an exclusion must name one of the pool's members (otherwise it silently benches nothing)"
                        ));
                    }
                }
            }
        }

        if let Some(crate::config::OnExhaustedCfg::FallbackPool(target)) = &pool_cfg.on_exhausted {
            if !cfg.pools.contains_key(target) {
                errors.push(format!(
                    "pool '{pool_name}' on_exhausted references unknown fallback pool '{target}'"
                ));
            } else if target == pool_name {
                errors.push(format!(
                    "pool '{pool_name}' on_exhausted references itself as its fallback pool ('{target}'); a self-referential fallback never engages (the runtime loop guard terminates it on re-entry) so it 503s exactly as having no fallback would. Point it at a different pool or remove on_exhausted"
                ));
            }
        }

        if let Some(crate::config::OnExhaustedCfg::Queue { max_ms }) = &pool_cfg.on_exhausted {
            let resolved_timeout_secs = pool_cfg
                .failover
                .as_ref()
                .map(|f| f.timeout_secs)
                .unwrap_or(crate::config::DEFAULT_FAILOVER_DEADLINE_SECS);
            let budget_ms = resolved_timeout_secs.saturating_mul(1000);
            if *max_ms == 0 {
                errors.push(format!(
                    "pool '{pool_name}' on_exhausted.queue.max_ms must be > 0; a 0 wait never queues (it is just `reject` with extra machinery)"
                ));
            } else if *max_ms > budget_ms {
                errors.push(format!(
                    "pool '{pool_name}' on_exhausted.queue.max_ms ({max_ms} ms) exceeds the resolved failover budget ({resolved_timeout_secs} s = {budget_ms} ms); a queue longer than the whole failover budget is clamped to it at runtime and never reaches its ceiling. Lower max_ms to <= {budget_ms} ms or raise failover.timeout_secs"
                ));
            }
        }

        if let Some(affinity) = &pool_cfg.affinity {
            if let Some(header_name) = &affinity.header_name {
                if header_name.is_empty() {
                    errors.push(format!(
                        "pool '{pool_name}' affinity.header_name must not be empty (an empty HTTP header field-name silently disables session affinity)"
                    ));
                }
                if !header_name.is_ascii() {
                    errors.push(format!(
                        "pool '{pool_name}' affinity.header_name '{header_name}' must be ASCII (an HTTP header field-name cannot contain non-ASCII bytes)"
                    ));
                } else if !header_name.is_empty()
                    && !busbar_contract::header::is_header_name_token(header_name.as_bytes())
                {
                    errors.push(format!(
                        "pool '{pool_name}' affinity.header_name must be a valid HTTP field-name"
                    ));
                }
                if header_name.len() > MAX_AFFINITY_HEADER_NAME_LEN {
                    errors.push(format!(
                        "pool '{}' affinity.header_name is {} chars; must be <= {}",
                        pool_name,
                        header_name.len(),
                        MAX_AFFINITY_HEADER_NAME_LEN
                    ));
                }
            }
        }
    }

    for (pool_name, pool_cfg) in cfg.plane_pools.values().flat_map(|pools| pools.iter()) {
        if let Some(breaker) = &pool_cfg.breaker {
            check_pool_breaker(pool_name, breaker, &mut errors);
        }
    }

    for pool_name in cfg.pools.keys() {
        let mut path: Vec<String> = Vec::new();
        let mut cursor: String = pool_name.clone();
        loop {
            if path.contains(&cursor) {
                let start = path.iter().position(|p| *p == cursor).unwrap_or(0);
                let ring = &path[start..];
                let min_member = ring
                    .iter()
                    .min()
                    .map(String::as_str)
                    .unwrap_or(cursor.as_str());
                if pool_name.as_str() == min_member && ring.len() > 1 {
                    let mut display: Vec<&str> = ring.iter().map(String::as_str).collect();
                    display.push(cursor.as_str());
                    errors.push(format!(
                        "fallback_pool cycle detected: {}; on_exhausted fallback chains must not loop — the runtime loop guard terminates a cycle on re-entry, so every pool in the ring 503s instead of degrading. Break the cycle (point one pool at a non-looping pool or remove its on_exhausted)",
                        display.join(" -> ")
                    ));
                }
                break;
            }

            let Some(next) = resolve_fallback_target(cfg, &cursor) else {
                break;
            };
            path.push(cursor);

            if !cfg.pools.contains_key(&next) {
                break;
            }
            cursor = next;
        }
    }

    for (hook_name, hook) in &cfg.hooks {
        if let Err(refusal) = validate_hook_timeout(hook_name, hook.timeout_ms) {
            errors.push(refusal);
        }
        if hook.plugin.trim().is_empty() {
            errors.push(format!(
                "hook '{hook_name}' names no plugin: set `module:` to a `kind: hook` plugin's \
                 signed-manifest name or alias"
            ));
        }

        if hook.prompt == crate::config::PromptAccess::Rw
            && hook.kind == crate::config::HookKind::Tap
        {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `prompt: rw`, but only a gate can rewrite (a tap \
                 never replies). Use `kind: gate`, or lower to `prompt: ro`."
            ));
        }

        if hook.default && hook.kind == crate::config::HookKind::Tap {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `default: true`, but a tap cannot be a pool's base \
                 ordering (it never replies). Only a gate can be the default."
            ));
        }
    }

    for hook_name in cfg.hooks.keys() {
        if crate::config::is_reserved_hook_name(hook_name) {
            errors.push(format!(
                "hook '{hook_name}' uses a reserved name (a built-in ranking strategy, auth module, \
                 or on_error terminal); rename the hook — a hook can never shadow a reserved word"
            ));
        }
    }

    {
        let mut defaults: Vec<&str> = cfg
            .hooks
            .iter()
            .filter(|(_, h)| h.default)
            .map(|(name, _)| name.as_str())
            .collect();
        if defaults.len() > 1 {
            defaults.sort_unstable();
            errors.push(format!(
                "more than one hook sets `default: true` ({}); at most one hook may be the default \
                 base ordering",
                defaults.join(", ")
            ));
        }
    }

    for (pool_name, pool_cfg) in &cfg.pools {
        for hook_name in &pool_cfg.gates {
            match cfg.hooks.get(hook_name) {
                None => errors.push(format!(
                    "pool '{pool_name}' references unknown hook '{hook_name}'; define it under \
                     top-level `hooks:`"
                )),
                Some(h) if h.kind != crate::config::HookKind::Gate => errors.push(format!(
                    "pool '{pool_name}' hook '{hook_name}' is a tap, but a hook named in a pool's \
                     `hooks:` list must be a gate (fire-and-wait); a tap cannot influence routing"
                )),
                Some(_) => {}
            }
        }
    }

    for (hook_name, hook) in &cfg.hooks {
        let mut visited: Vec<&str> = vec![hook_name.as_str()];
        let mut current: &str = hook.on_error.as_str();
        loop {
            if crate::config::on_error_terminal(current).is_some() {
                break;
            }

            if crate::config::is_strategy_name(current) {
                if !crate::preflight::builtin_ranking_known(current) {
                    errors.push(format!(
                        "hook '{hook_name}' on_error names the built-in ranking strategy \
                         '{current}' but this binary was built WITHOUT the `hooks-ranking` \
                         feature. Rebuild with default features or use nothing|weighted|reject|first."
                    ));
                }
                break;
            }
            if visited.contains(&current) {
                errors.push(format!(
                    "hook on_error chain does not terminate: {} -> {current} is a cycle; every \
                     chain must bottom out on nothing|weighted|reject|first or a ranking strategy",
                    visited.join(" -> ")
                ));
                break;
            }
            let Some(next) = cfg.hooks.get(current) else {
                errors.push(format!(
                    "hook '{hook_name}' on_error names unknown fallback '{current}'; use a \
                     reserved terminal (nothing|weighted|reject|first), a ranking strategy, or another \
                     gate in the `hooks:` registry"
                ));
                break;
            };
            if next.kind != crate::config::HookKind::Gate {
                errors.push(format!(
                    "hook '{hook_name}' on_error fallback '{current}' is a tap; a fallback must \
                     be a gate (fire-and-wait) — a tap cannot decide"
                ));
                break;
            }
            visited.push(current);
            current = next.on_error.as_str();
        }
    }

    if let Some(public_url) = cfg.public_url.as_deref() {
        validate_public_url(public_url, &cfg.blocked_metadata_hosts, &mut errors);
    }

    if let Some(auth) = cfg.auth.as_ref() {
        let chain_modules: std::collections::HashSet<&str> = auth
            .chain
            .iter()
            .chain(auth.admin_auth.iter())
            .flat_map(|e| [e.module.as_str(), e.name.as_str()])
            .chain(auth.methods.keys().map(String::as_str))
            .collect();

        if cfg.public_url.is_none() && auth.methods.values().any(|m| m.browser_login.is_some()) {
            errors.push(
                "auth.methods has a `browser_login` method but top-level `public_url:` is unset; a \
                 hosted login button needs busbar's public base to build the authorize/redirect \
                 URLs — set `public_url: https://<busbar-host>`"
                    .to_string(),
            );
        }

        if let Some(ttl) = auth.key_ttl.as_deref() {
            if let Err(e) = crate::config::parse::parse_duration_secs(ttl) {
                errors.push(format!("auth.key_ttl '{ttl}' is not a valid duration: {e}"));
            }
        }

        let policy = &auth.policy;
        let parse_policy_ttl = |label: &str, ttl: &str, errors: &mut Vec<String>| -> Option<u64> {
            match crate::config::parse::parse_duration_secs(ttl) {
                Ok(secs) => Some(secs),
                Err(e) => {
                    errors.push(format!("{label} '{ttl}' is not a valid duration: {e}"));
                    None
                }
            }
        };
        let default_secs = policy
            .default_ttl
            .as_deref()
            .and_then(|t| parse_policy_ttl("auth.policy.default_ttl", t, &mut errors));
        let max_secs = policy
            .max_ttl
            .as_deref()
            .and_then(|t| parse_policy_ttl("auth.policy.max_ttl", t, &mut errors));
        if let (Some(d), Some(m)) = (default_secs, max_secs) {
            if d > m {
                errors.push(format!(
                    "auth.policy.default_ttl ('{}', {d}s) exceeds auth.policy.max_ttl ('{}', {m}s); \
                     the default a mint falls back to cannot be longer than the ceiling",
                    policy.default_ttl.as_deref().unwrap_or(""),
                    policy.max_ttl.as_deref().unwrap_or(""),
                ));
            }
        }
        for (role, ceiling) in &policy.mint_ceilings {
            if let (Some(block), Some(modes)) = (&policy.binding_modes, &ceiling.binding_modes) {
                for mode in modes.iter().filter(|m| !block.contains(m)) {
                    errors.push(format!(
                        "auth.policy.mint_ceilings.{role}.binding_modes names '{}', which \
                         auth.policy.binding_modes does not allow; a per-role ceiling cannot \
                         widen the deployment-wide binding modes",
                        mode.as_str()
                    ));
                }
            }
            if let Some(ttl) = ceiling.max_ttl.as_deref() {
                if let Some(c) = parse_policy_ttl(
                    &format!("auth.policy.mint_ceilings.{role}.max_ttl"),
                    ttl,
                    &mut errors,
                ) {
                    if let Some(m) = max_secs {
                        if c > m {
                            errors.push(format!(
                                "auth.policy.mint_ceilings.{role}.max_ttl ('{ttl}', {c}s) exceeds \
                                 auth.policy.max_ttl ({m}s); a per-role ceiling cannot exceed the \
                                 deployment-wide mint ceiling"
                            ));
                        }
                    }
                }
            }
        }
        for (module, roles) in &auth.role_bindings {
            if !chain_modules.contains(module.as_str()) {
                errors.push(format!(
                    "role_bindings names module '{module}', which appears in neither auth.chain \
                     nor auth.admin_auth; a binding under an inactive module grants nothing. \
                     Add the module to the chain, e.g.:\n\n    auth:\n      chain:\n        - \
                     {module}: {{ settings: {{}} }}\n"
                ));
            }
            for (role, binding) in roles {
                if reserved_operator_principal_id(role) {
                    errors.push(format!(
                        "role_bindings.{module} binds role '{role}', which shadows the reserved \
                         operator principal id; choose another role name"
                    ));
                }
                if let Some(scope) = binding.admin_scope.as_deref() {
                    if busbar_contract::authz::Scope::parse(scope).is_none() {
                        errors.push(format!(
                            "role_bindings.{module}.{role} has unknown admin_scope '{scope}': \
                             expected read-only or full"
                        ));
                    }
                }

                match binding.verb_grant() {
                    None | Some(Ok(crate::config::VerbGrant::All)) => {}
                    Some(Err(shape)) => errors.push(format!(
                        "role_bindings.{module}.{role}.verbs must be \"{all}\" or a list of admin \
                         verb names, not {shape}",
                        all = crate::config::ALL_ADMIN_VERBS
                    )),
                    Some(Ok(crate::config::VerbGrant::Named(names))) => {
                        for name in names {
                            if crate::admin::seam::admin_verb_rung(&name).is_none() {
                                errors.push(format!(
                                    "role_bindings.{module}.{role}.verbs names unknown admin verb \
                                     '{name}': expected \"{all}\" or operation names from the \
                                     admin verb table (e.g. get_keys, post_keys)",
                                    all = crate::config::ALL_ADMIN_VERBS
                                ));
                            }
                        }
                    }
                }

                for field in binding.plane_grants.keys() {
                    let declared = crate::governance::plane_grant_kind(field)
                        .is_some_and(|kind| crate::governance::plane_declares_kind(&kind));
                    if !declared {
                        errors.push(format!(
                            "role_bindings.{module}.{role}.{field} grants a scope kind no \
                             installed plane declares; remove it, or install the plane whose \
                             grants it names"
                        ));
                    }
                }
                if let Some(group) = binding.group.as_deref() {
                    if !cfg.groups.contains_key(group) {
                        errors.push(format!(
                            "role_bindings.{module}.{role} names group '{group}', which does not \
                             exist.\nPaste this under groups and set its limits:\n\n    \
                             {group}:\n      limits:\n        - {{ requests: 0, per: minute }}\n"
                        ));
                    }
                }
            }
        }

        for entry in auth.chain.iter().chain(auth.admin_auth.iter()) {
            if let Some(scope) = entry.max_admin_scope.as_deref() {
                match crate::config::parse::parse_ceiling(
                    &format!("auth chain entry '{}'", entry.module),
                    scope,
                ) {
                    Err(e) => errors.push(e),
                    Ok(busbar_contract::authz::Scope::Full) => diag_warn!(
                        CONFIG_AUTH_CHAIN_FULL_SCOPE,
                        module = %entry.module,
                        "auth chain entry grants max_admin_scope: full - principals identified by \
                         this module can hold FULL admin authority (the default ceiling is \
                         read-only); make sure this chain is trusted end to end"
                    ),
                    Ok(_) => {}
                }
            }

            if entry.token.is_some() && !crate::config::names_operator(&entry.module) {
                errors.push(operator::misplaced_token(
                    operator_provider(),
                    &entry.module,
                ));
            }
        }
    }

    for name in &cfg.global_hooks {
        if !cfg.hooks.contains_key(name) {
            errors.push(format!(
                "global_hooks references unknown hook '{name}'; define it under top-level `hooks:`"
            ));
        }
    }

    for (pool_name, pool_cfg) in &cfg.pools {
        let name = pool_cfg.policy.native_name();
        if !matches!(pool_cfg.policy, crate::config::PoolPolicy::Named(_))
            && !plugins_enabled
            && name.is_some_and(|n| !crate::preflight::builtin_ranking_known(n))
        {
            errors.push(format!(
                "pool '{pool_name}' names the {:?} ranking strategy but this binary was built \
                 WITHOUT the `hooks-ranking` feature — the built-in ranking strategies are absent. \
                 Rebuild with default features, use `hooks: [weighted]` (or name no strategy), or \
                 reference an external ranking hook.",
                pool_cfg.policy
            ));
        }
    }

    let endpoint_section = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
    if cfg.endpoint_resource(endpoint_section).is_some()
        && cfg.auth.as_ref().is_none_or(|a| a.chain.is_empty())
    {
        let decl = crate::plane_driver::registry::plane_decl_for_config_section(endpoint_section);
        let key = decl.map(|d| d.key).unwrap_or("endpoint");
        let noun = decl.map(|d| d.subject_noun).unwrap_or("endpoint");
        errors.push(format!(
            "`{key}:` is configured but auth.chain is empty, which serves the {noun} endpoint to \
             ANONYMOUS callers — and a request that carries no key is never narrowed by one, so it \
             runs with WILDCARD grants over every registered subject on that plane. It also leaves \
             `upstream::authorise` with no inbound grant to bind busbar's outbound credentials to. \
             Close the data-plane chain (`auth: {{ chain: [keys] }}`, or an IdP auth plugin), or \
             remove the `{key}:` block if this deployment is not a {noun}."
        ));
    }

    if let Some(auth) = &cfg.auth {
        for entry in &auth.chain {
            let name = entry.module.as_str();
            if name == "tokens" || name == "static-tokens" {
                errors.push(format!(
                    "auth.chain names '{name}': the static-token allowlist module was REMOVED \
                     in 1.5.0. Data-plane auth is `keys` (busbar-signed keys, minted via \
                     POST /api/v1/admin/keys) and IdP auth plugins - write:\n\n    auth:\n      \
                     chain:\n        - keys\n"
                ));
            }
        }

        let verifies_signed_keys = auth
            .chain
            .iter()
            .any(|e| e.module == crate::config::KEYS_MODULE);
        if verifies_signed_keys && auth.signing_key.is_none() {
            errors.push(
                "auth.signing_key is required for signed-token auth (auth.chain names the \
                 built-in `keys` verifier), but none is set - and busbar no longer auto-generates \
                 one. Generate a key with `busbar --generate-signing-key`, then set auth.signing_key \
                 to a secret reference for it ({file: /path} or {env: VAR} - a SHARED secret across \
                 nodes for a fleet)."
                    .to_string(),
            );
        }

        if verifies_signed_keys && !auth.usable_mint_path() {
            errors.push(operator::no_mint_path(operator_provider()));
        }
        if verifies_signed_keys && auth.admin_auth.is_empty() {
            diag_warn!(
                CONFIG_OPEN_ADMIN_MINT,
                "auth.chain names `keys` and auth.admin_auth is explicitly empty (open admin) — \
                 ANYONE can mint virtual keys through the admin API. Acceptable only for dev."
            );
        }

        let any_passthrough = cfg.upstream_credentials == crate::auth::UpstreamCreds::Passthrough
            || cfg
                .pools
                .values()
                .any(|p| p.upstream_credentials == Some(crate::auth::UpstreamCreds::Passthrough));
        if any_passthrough {
            for (provider_name, provider_cfg) in &cfg.providers {
                let resolved_key = crate::config::secret::resolve_linked_string_at_config(
                    &provider_cfg.api_key,
                    &busbar_contract::config_time::ConfigScope::config_time(),
                )
                .unwrap_or_default();
                if !resolved_key.expose(&crate::seal::lend()).trim().is_empty() {
                    diag_warn!(
                        CONFIG_PASSTHROUGH_UNUSED_APIKEY,
                        provider = %provider_name,
                        api_key = %provider_cfg.api_key.describe(),
                        "upstream_credentials: passthrough with a NON-EMPTY configured api_key for \
                         this provider: under passthrough the upstream key is \
                         caller_token.unwrap_or(\"\"), so the configured api_key is NEVER forwarded \
                         (a caller presents their own token, or an unauthenticated caller forwards an \
                         empty credential the provider rejects). The configured key is inert dead \
                         config. If you intended static-key gating, use upstream_credentials: own \
                         (plus an auth chain); otherwise clear the referenced secret (a passthrough \
                         provider that signs each request per-call needs no static key)."
                    );
                }
            }
        }
    }

    use crate::export::plugin::check;
    let sinks = &mut |e: &mut Vec<String>| check(&cfg.export, CheckPhase::Limits, e);
    validate_limits_with(&cfg.limits, &mut errors, sinks);
    check(&cfg.export, CheckPhase::Instances, &mut errors);

    {
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for pool_cfg in cfg.pools.values() {
            for m in &pool_cfg.members {
                if let Some(c) = m.context_max {
                    match seen.get(m.model.as_str()) {
                        Some(existing) if *existing != c => {
                            errors.push(format!(
                                "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                                m.model, existing, c
                            ));
                        }
                        _ => {
                            seen.insert(m.model.as_str(), c);
                        }
                    }
                }
            }
        }
    }

    validate_cost_model(cfg, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_hook_timeout(name: &str, timeout_ms: u64) -> Result<(), String> {
    if timeout_ms > MAX_DURATION_MS {
        return Err(format!(
            "hook '{name}' timeout_ms ({timeout_ms}) exceeds the maximum of {MAX_DURATION_MS} ms \
             (30 years, the async runtime's own 'never' horizon); a larger duration overflows \
             the clock arithmetic it feeds"
        ));
    }
    Ok(())
}

fn check_pool_breaker(
    pool_name: &str,
    breaker: &crate::config::BreakerCfg,
    errors: &mut Vec<String>,
) {
    if breaker.base_cooldown_secs == 0 {
        errors.push(format!(
            "pool '{pool_name}' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off"
        ));
    }
    if breaker.max_cooldown_secs == 0 {
        errors.push(format!(
            "pool '{pool_name}' breaker max_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off"
        ));
    }

    if breaker.max_cooldown_secs < breaker.base_cooldown_secs {
        errors.push(format!(
            "pool '{}' breaker max_cooldown_secs ({}) must be >= base_cooldown_secs ({})",
            pool_name, breaker.max_cooldown_secs, breaker.base_cooldown_secs
        ));
    }
    if let Some(trip) = &breaker.trip {
        if trip.min_requests == 0 {
            errors.push(format!(
                "pool '{pool_name}' breaker trip.min_requests must be >= 1 (got 0)"
            ));
        }

        if trip.window_secs == 0 {
            errors.push(format!(
                "pool '{pool_name}' breaker trip.window_secs must be >= 1 (got 0)"
            ));
        }
        match trip.mode {
            crate::config::BreakerTripMode::ErrorRate => {
                if !(trip.threshold > 0.0 && trip.threshold <= 1.0) {
                    errors.push(format!(
                        "pool '{}' breaker trip.threshold must be in (0.0, 1.0] for error_rate mode (got {})",
                        pool_name, trip.threshold
                    ));
                }
            }
            crate::config::BreakerTripMode::Consecutive => {
                if trip.consecutive_n == 0 {
                    errors.push(format!(
                        "pool '{pool_name}' breaker trip.consecutive_n must be >= 1 for consecutive mode (got 0)"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
fn validate_limits(limits: &crate::config::LimitsResolved, errors: &mut Vec<String>) {
    validate_limits_with(limits, errors, &mut |_| {});
}

fn validate_limits_with(
    limits: &crate::config::LimitsResolved,
    errors: &mut Vec<String>,
    sinks: &mut dyn FnMut(&mut Vec<String>),
) {
    use crate::config::{REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR};

    validate_limit_ceilings(limits, errors);

    if limits.upstream_request_timeout_secs < 1 {
        errors.push(
            "limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call \
             instantly)"
                .to_string(),
        );
    }
    if limits.tls_handshake_timeout_secs < 1 {
        errors.push(
            "limits.tls_handshake_timeout_secs must be >= 1 (0 would abort every TLS handshake)"
                .to_string(),
        );
    }
    if limits.request_body_read_timeout_secs < 1 {
        errors.push(
            "limits.request_body_read_timeout_secs must be >= 1 (0 would abort every request whose \
             body is not instantly buffered)"
                .to_string(),
        );
    }
    sinks(errors);

    if limits.max_honored_retry_after_secs < 1 {
        errors.push(
            "limits.max_honored_retry_after_secs must be >= 1 (a 0 ceiling would clamp every honored \
             Retry-After to 0)"
                .to_string(),
        );
    }
    if limits.hard_down_cooldown_secs < 1 {
        errors.push(
            "limits.hard_down_cooldown_secs must be >= 1 (a 0 sticky cooldown would re-ready a \
             hard-down lane immediately)"
                .to_string(),
        );
    }

    if limits.request_body_max_bytes < REQUEST_BODY_MAX_BYTES_FLOOR {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) is below the {REQUEST_BODY_MAX_BYTES_FLOOR}-byte floor \
             — too small to admit a minimal request",
            limits.request_body_max_bytes
        ));
    }
    if limits.request_body_max_bytes > REQUEST_BODY_MAX_BYTES_CEIL {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) exceeds the {REQUEST_BODY_MAX_BYTES_CEIL}-byte ceiling \
             — the body is buffered per request, so this risks memory exhaustion",
            limits.request_body_max_bytes
        ));
    }
    if limits.datagram_line_memory_bytes == Some(0) {
        errors.push(
            "limits.datagram_line_memory_bytes must be >= 1 when set (omit it or use null to disable the limit)"
                .to_string(),
        );
    }

    if limits.upstream_error_body_max_bytes < 1 {
        errors.push(
            "limits.upstream_error_body_max_bytes must be >= 1 (0 would buffer no upstream error body)"
                .to_string(),
        );
    }

    if limits.default_max_tokens < 1 {
        errors.push(
            "limits.default_max_tokens must be >= 1 (0 would be injected verbatim and rejected upstream)"
                .to_string(),
        );
    }

    if limits.default_probe_interval_secs < 1 {
        errors.push("health.default_probe_interval_secs must be >= 1".to_string());
    }
    if limits.default_probe_timeout_secs < 1 {
        errors.push("health.default_probe_timeout_secs must be >= 1".to_string());
    }
    if limits.default_policy_timeout_ms < 1 {
        errors.push(
            "routing.default_policy_timeout_ms must be >= 1 (0 would make every policy decision time \
             out instantly)"
                .to_string(),
        );
    }

    if limits.rate_sweep_interval == 0 {
        errors.push(
            "advanced.rate_sweep_interval is 0; must be >= 1. A value of 0 disables the rate-map \
             idle-entry sweep, leaking entries for silent keys until restart. The default is 256 \
             (sweep every 256 admissions); use a larger value to make sweeps rarer."
                .to_string(),
        );
    }

    if limits.max_inbound_concurrent > MAX_SEMAPHORE_PERMITS {
        errors.push(format!(
            "limits.max_inbound_concurrent must be <= {MAX_SEMAPHORE_PERMITS} (tokio::sync::\
             Semaphore's hard permit ceiling — a value above it panics at build time instead of \
             failing validation), or 0 to disable the inbound-concurrency layer entirely"
        ));
    }
}

fn validate_limit_ceilings(limits: &crate::config::LimitsResolved, errors: &mut Vec<String>) {
    let crate::config::LimitsResolved {
        upstream_request_timeout_secs,
        pool_idle_timeout_secs,
        hard_down_cooldown_secs,
        tls_handshake_timeout_secs,
        request_body_read_timeout_secs,
        max_honored_retry_after_secs,
        default_probe_interval_secs,
        default_probe_timeout_secs,

        usage_flush_interval_ms,
        default_policy_timeout_ms,

        request_body_max_bytes: _,
        max_inbound_concurrent: _,

        datagram_line_memory_bytes: _,

        pool_max_idle_per_host: _,
        max_keys_per_principal: _,
        max_auto_provisioned_groups: _,
        hook_content_max_bytes: _,
        upstream_error_body_max_bytes: _,
        key_gauge_limit: _,

        rate_sweep_interval: _,

        default_max_tokens: _,
        reasoning_effort_budgets: _,

        upstream_http1_only: _,
        upstream_h2_prior_knowledge: _,
    } = limits;
    let secs = [
        (
            "limits.upstream_request_timeout_secs",
            *upstream_request_timeout_secs,
        ),
        ("limits.pool_idle_timeout_secs", *pool_idle_timeout_secs),
        ("limits.hard_down_cooldown_secs", *hard_down_cooldown_secs),
        (
            "limits.tls_handshake_timeout_secs",
            *tls_handshake_timeout_secs,
        ),
        (
            "limits.request_body_read_timeout_secs",
            *request_body_read_timeout_secs,
        ),
        (
            "limits.max_honored_retry_after_secs",
            *max_honored_retry_after_secs,
        ),
        (
            "health.default_probe_interval_secs",
            *default_probe_interval_secs,
        ),
        (
            "health.default_probe_timeout_secs",
            *default_probe_timeout_secs,
        ),
    ];
    for (name, v) in secs {
        if v > MAX_DURATION_SECS {
            errors.push(format!(
                "{name} ({v}) exceeds the maximum of {MAX_DURATION_SECS} s (30 years, the async \
                 runtime's own 'never' horizon); a larger duration overflows the clock arithmetic \
                 it feeds. Lower it to <= {MAX_DURATION_SECS}"
            ));
        }
    }
    let millis = [
        ("advanced.usage_flush_interval_ms", *usage_flush_interval_ms),
        (
            "routing.default_policy_timeout_ms",
            *default_policy_timeout_ms,
        ),
    ];
    for (name, v) in millis {
        if v > MAX_DURATION_MS {
            errors.push(format!(
                "{name} ({v}) exceeds the maximum of {MAX_DURATION_MS} ms (30 years, the async \
                 runtime's own 'never' horizon); a larger duration overflows the clock arithmetic \
                 it feeds. Lower it to <= {MAX_DURATION_MS}"
            ));
        }
    }
}

fn priced_classes(
    d: &crate::plane_driver::registry::PlaneDecl,
) -> impl Iterator<Item = &'static str> + Clone + '_ {
    (d.billable_classes.iter())
        .map(|c| c.class)
        .filter(|c| !d.fee_units.contains(c))
}

fn validate_cost_model(cfg: &RootCfg, errors: &mut Vec<String>) {
    if let Some(card) = &cfg.rate_card {
        for (key, r) in card {
            let (plane, lane) = split_plane_lane(key);
            let at = crate::plane_driver::registry::plane_decl_for(plane)
                .map_or(plane, |d| d.config_section);
            let path = format!(
                "{at}{}rate_card['{lane}']",
                if at.is_empty() { "" } else { "." }
            );
            let tiers = [
                ("input_utok", r.input_utok),
                ("output_utok", r.output_utok),
                ("cache_read_utok", r.cache_read_utok),
                ("cache_write_utok", r.cache_write_utok),
            ];
            for (tier, v) in tiers {
                if !v.is_finite() || v < 0.0 {
                    errors.push(format!(
                        "{path}.{tier} must be a finite, non-negative \
                         number of micro-units per token (got {v})"
                    ));
                } else if busbar_kernel_ledger::cost::representable_nano_rate(v).is_none() {
                    errors.push(format!(
                        "{path}.{tier} = {v} micro-units per token is a rate the card \
                         cannot hold (a non-zero rate is a whole number of nano-units, at most three \
                         decimal places, up to about 1.8e16; it is never rounded), so the class \
                         would bill as unpriced; configure 0 to make it free, or an exact rate"
                    ));
                }
            }

            for class in r
                .units
                .keys()
                .filter(|c| busbar_contract::records::RESERVED_UNITS.contains(&c.as_str()))
            {
                errors.push(format!(
                    "{path}.units.{class} names a reserved class; price it with {class}_utok"
                ));
            }
            if !lane.is_empty()
                && tiers.iter().all(|(_, v)| v.is_finite() && *v == 0.0)
                && r.units.is_empty()
            {
                diag_warn!(
                    CONFIG_RATE_CARD_ALL_ZERO,
                    model = %key,
                    "rate_card entry for model '{key}' prices every tier at zero: its token usage \
                     meters as FREE and is uncapped by any budget: limit. If intentional, ignore; \
                     otherwise fill in the model's rate_card rates."
                );
            }
        }

        let flat_card = flat_card_present(card.keys().map(|k| split_plane_lane(k).0));
        let mut model_names: Vec<&String> = cfg.models.keys().collect();
        model_names.sort();
        let missing: Vec<&str> = model_names
            .iter()
            .filter(|name| flat_card && !card.contains_key(name.as_str()))
            .map(|name| name.as_str())
            .collect();
        if !missing.is_empty() {
            let width = missing.iter().map(|m| m.len()).max().unwrap_or(0) + 1;
            let stub: String = missing
                .iter()
                .map(|m| {
                    format!(
                        "    {:width$} {{ input_utok: 0, output_utok: 0, cache_read_utok: 0, cache_write_utok: 0 }}\n",
                        format!("{m}:")
                    )
                })
                .collect();
            errors.push(format!(
                "rate_card is present but {} configured model{} no rate entry (rate_card is \
                 AUTHORITATIVE and COMPLETE: you either price nothing or price everything).\n\
                 Paste these under rate_card and fill in your rates (micro-units per token):\n\n{stub}",
                missing.len(),
                if missing.len() == 1 { " has" } else { "s have" },
            ));
        }

        for model in card.keys().filter(|k| !k.contains(PLANE_LANE_SEP)) {
            if !cfg.models.contains_key(model) {
                errors.push(format!(
                    "rate_card names model '{model}', which is not defined under models: \
                     (a rate entry is keyed by the CONFIG model name); remove it or fix the name"
                ));
            }
        }

        for d in crate::plane_driver::registry::plane_decls() {
            let own = if d.fallback { "" } else { d.key };
            let on: Vec<_> = card
                .iter()
                .filter(|(k, _)| split_plane_lane(k).0 == own)
                .collect();
            let entry = on.iter().any(|(k, _)| !split_plane_lane(k).1.is_empty());
            let unset = |c: &&str| {
                !(entry && busbar_contract::records::RESERVED_UNITS.contains(c)
                    || on.iter().any(|(_, r)| r.units.contains_key(*c)))
            };
            let declared = priced_classes(d);
            let missing: Vec<&str> = declared.clone().filter(unset).collect();
            let present = if d.fallback {
                flat_card
            } else {
                !on.is_empty()
            };
            if present && !missing.is_empty() {
                errors.push(format!(
                    "{}.rate_card does not configure billable unit(s) {} declared by this plane; \
                     add them (0 to make them free)",
                    d.config_section,
                    missing.join(", ")
                ));
            }

            let unknown: std::collections::BTreeSet<&str> = (on.iter())
                .flat_map(|(_, r)| r.units.keys().map(String::as_str))
                .filter(|k| !declared.clone().any(|c| c == *k))
                .collect();
            if !unknown.is_empty() {
                errors.push(format!(
                    "{}.rate_card configures unit(s) {} not declared by this plane (declared: {}); \
                     remove them or fix the name",
                    d.config_section,
                    unknown.into_iter().collect::<Vec<_>>().join(", "),
                    Some(declared.collect::<Vec<_>>().join(", "))
                        .filter(|l| !l.is_empty())
                        .unwrap_or_else(|| "none".into())
                ));
            }
        }
    }

    if let Some(card) = &cfg.rate_card {
        for defs in cfg.plane_defs.values() {
            let lanes = defs.ledger_lanes();
            let missing: Vec<&str> = (lanes.iter().map(String::as_str))
                .filter(|l| {
                    let plane = split_plane_lane(l).0;
                    card.keys().any(|k| split_plane_lane(k).0 == plane) && !card.contains_key(*l)
                })
                .collect();
            let Some(d) = missing
                .first()
                .and_then(|l| plane_decl_for(split_plane_lane(l).0))
            else {
                continue;
            };
            let zero = priced_classes(d)
                .map(|c| format!("{c}: 0"))
                .collect::<Vec<_>>()
                .join(", ");
            let stub: String = (missing.iter())
                .map(|l| format!("    {}: {{ units: {{ {zero} }} }}\n", split_plane_lane(l).1))
                .collect();
            errors.push(format!(
                "{section}.rate_card is present but {n} {noun}{s} no rate entry (a present card is \
                 AUTHORITATIVE and COMPLETE: you either price nothing or price everything).\n\
                 Paste these under {section}.rate_card and fill in your rates:\n\n{stub}",
                section = d.config_section,
                n = missing.len(),
                noun = d.subject_noun,
                s = if missing.len() == 1 { " has" } else { "s have" },
            ));
        }
    }

    if cfg.per_request_fee < 0 {
        errors.push(format!(
            "per_request_fee must be >= 0 (got {}); a negative fee would credit every request",
            cfg.per_request_fee
        ));
    }

    let fee_decls = (cfg.plane_fees.iter()).filter_map(|(p, f)| Some((plane_decl_for(p)?, f)));
    for (d, f) in fee_decls {
        let counted = Some(d.fee_units.join(", ")).filter(|l| !l.is_empty());
        for (unit, fee) in [(PER_REQUEST, f.per_request), (PER_SESSION, f.per_session)] {
            if fee != 0 && !d.fee_units.contains(&unit) {
                errors.push(format!(
                    "{}.fees.{unit} is not counted by this plane (counted: {}); remove it",
                    d.config_section,
                    counted.as_deref().unwrap_or("none")
                ));
            }
        }
    }

    crate::config::groups::validate_groups(&cfg.groups, &|p| cfg.pools.contains_key(p), errors);
    for (name, g) in &cfg.groups {
        for limit in &g.limits {
            if limit.amount == 0 {
                errors.push(format!(
                    "groups.{name} has a `{}` limit of 0, which rejects every request through the \
                     group from the first admission; set a positive amount, or set `enabled: \
                     false` to freeze the group explicitly",
                    limit.metric.as_str()
                ));
            }
        }
    }

    match &cfg.store {
        None => errors.push(crate::config::store_required()),
        Some(store) if store.module.trim().is_empty() => {
            errors.push(format!(
                "store.module must be non-empty; use `{}` (the compiled-in RAM store) or a \
                 store plugin name/alias ({} | <third-party>)",
                crate::config::migrated_store_module(),
                crate::config::migrate::legacy_store_text("module_examples")
            ));
        }
        Some(_) => {}
    }

    let sugars = crate::config::secret::sugars();
    let mut check_secret = |what: String, r: &crate::config::SecretRef| {
        if r.is_none() {
            if !keyless_credential_allowed(&what) {
                errors.push(format!(
                    "{what}: `none` declares that there is NO credential, which is only meaningful \
                     for a provider `api_key` (a keyless local upstream such as ollama or vLLM); \
                     {what} requires a real secret reference, e.g. \
                     {what}: {}",
                    example_reference(&sugars, "MY_SECRET_VAR")
                ));
            }

            return;
        }
        if let Some(refusal) = declared_setting_refusal(&sugars, &what, r) {
            errors.push(refusal);
        }
    };

    for (what, r) in secret_refs(cfg) {
        check_secret(what, r);
    }

    let per_reference = sugars
        .iter()
        .map(|s| format!("`{}`", s.setting))
        .collect::<Vec<_>>()
        .join(" / ");
    for module in cfg.secrets.keys() {
        if crate::config::secret::is_linked_secret(module) {
            errors.push(format!(
                "secrets.{module}: the built-in '{module}' secret module takes no module-level \
                 config; its settings ({per_reference}) belong on each individual secret \
                 reference, not in the top-level `secrets:` block"
            ));
        }
    }

    let token = cfg.auth.as_ref().and_then(|a| a.admin_token_ref());
    if token.is_some() && !operator::answered(operator_provider()) {
        errors.push(operator::unanswered_token(operator_provider()));
    }
}

fn example_reference(sugars: &busbar_contract::secret_ref::Sugars, var: &str) -> String {
    match sugars.with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL) {
        Some(s) => format!("{{ {}: {var} }}", s.word),
        None => "{ module: <secret-module>, settings: {…} }".to_string(),
    }
}

fn declared_setting_refusal(
    sugars: &busbar_contract::secret_ref::Sugars,
    what: &str,
    r: &crate::config::SecretRef,
) -> Option<String> {
    let sugar = sugars.get(&r.module)?;
    match r.settings.get(&sugar.setting).and_then(|v| v.as_str()) {
        None => Some(format!(
            "{what}: secret module '{}' requires settings.{} ({})",
            r.module, sugar.setting, sugar.names
        )),
        Some(v) if v.trim().is_empty() => Some(format!(
            "{what}: secret module '{}' requires a NON-EMPTY settings.{} ({})",
            r.module, sugar.setting, sugar.names
        )),
        Some(_) => None,
    }
}

fn admin_root_segment() -> &'static str {
    crate::auth::ADMIN_PATH.trim_start_matches('/')
}

fn reserved_operator_principal_id(role: &str) -> bool {
    role == crate::config::operator_principal_id() && operator::answered(operator_provider())
}

fn reserved_admin_name(name: &str) -> bool {
    name.split('/').next() == Some(admin_root_segment())
}

fn reserved_legacy_admin_name(name: &str) -> bool {
    name.split('/').next() == Some("admin")
}

fn resolve_fallback_target(cfg: &RootCfg, pool_name: &str) -> Option<String> {
    match cfg.pools.get(pool_name)?.on_exhausted.as_ref()? {
        crate::config::OnExhaustedCfg::FallbackPool(target) => Some(target.clone()),
        _ => None,
    }
}

pub(crate) fn validate_public_url(url: &str, blocked: &[String], errors: &mut Vec<String>) {
    let is_https = scheme_is(url, "https");
    let is_http = scheme_is(url, "http");
    if !is_https && !is_http {
        errors.push(format!(
            "public_url must be an absolute http(s) URL (got '{url}')"
        ));
        return;
    }
    let Some(host) = extract_normalized_host(url) else {
        errors.push(format!("public_url '{url}' has no host"));
        return;
    };
    if is_http && !host_is_private_or_loopback(&host) {
        errors.push(format!(
            "public_url must use https for a public host (got '{url}'); plaintext http is permitted \
             only for a loopback/private base"
        ));
    }

    if let Some((_, rest)) = url.split_once("://") {
        let rest = rest.replace('\\', "/");
        if let Some(pos) = rest.find(['/', '?', '#']) {
            let delim = rest.as_bytes()[pos];
            let tail = &rest[pos + 1..];
            if delim != b'/' || !tail.is_empty() {
                errors.push(format!(
                    "public_url must be a bare origin (scheme://host[:port]) with no path, query, or \
                     fragment (got '{url}'); BYOK clients append their own suffix"
                ));
            }
        }
    }

    if let Some(bad) = ssrf_blocked_host(url, &[], false, blocked) {
        errors.push(format!(
            "public_url '{url}' targets a blocked cloud-metadata host '{bad}'"
        ));
    }
}

fn reject_cidr_metadata_entries(key: &str, entries: &[String], errors: &mut Vec<String>) {
    for entry in entries {
        if entry.contains('/') {
            errors.push(format!(
                "{key} entry '{entry}' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16')"
            ));
        }
    }
}

fn reject_unmappable_metadata_entries(key: &str, entries: &[String], errors: &mut Vec<String>) {
    for entry in entries {
        if let Some(line) = unmappable_metadata_refusal(key, entry) {
            errors.push(line);
        }
    }
}

fn unmappable_metadata_refusal(key: &str, entry: &str) -> Option<String> {
    if entry.contains('/') {
        return None;
    }
    let (why, fix) = unmappable_metadata_entry(entry)?;
    Some(format!(
        "{key} entry '{entry}' names no usable host: {why}, so it could never match a \
         destination. {fix}"
    ))
}

fn unmappable_metadata_entry(entry: &str) -> Option<(&'static str, &'static str)> {
    let trimmed = entry.trim();
    if busbar_kernel_egress::trust::net::list_entry_host(trimmed).is_err() {
        return Some((
            "UTS #46 refuses it, so it is no name a URL client would dial",
            "Write the host in ASCII (an internationalized name as its punycode 'xn--' form), or \
             remove it",
        ));
    }
    busbar_contract::net::judged_host(trimmed).err()?;
    let bare = trimmed.trim_start_matches('[');
    let zone = bare
        .find('%')
        .is_some_and(|at| bare[..at].parse::<std::net::Ipv6Addr>().is_ok());
    Some(if trimmed.contains('%') && !zone {
        (
            "it holds a '%' escape outside an IPv6 zone id, which a URL client decodes before it \
             dials",
            "Write the host decoded (the name or address it spells), or remove it",
        )
    } else {
        (
            "its last label reads as a number but it is no IPv4 address a URL client reads",
            "Write an address as a dotted quad, or a name whose last label is not a number, or \
             remove it",
        )
    })
}

pub(crate) fn metadata_entry_names_no_host(entry: &str) -> Option<&'static str> {
    if entry.contains('/') {
        return None;
    }
    unmappable_metadata_entry(entry).map(|(why, _)| why)
}

fn warn_refused_provider_destinations(cfg: &RootCfg) {
    if !cfg.guard.block_private_addresses {
        return;
    }
    let mut providers: Vec<(&String, &crate::config::ResolvedProvider)> =
        cfg.providers.iter().collect();
    providers.sort_by(|a, b| a.0.cmp(b.0));
    for (name, p) in providers {
        let urls = [
            ("base_url", Some(p.base_url.as_str())),
            ("token_url", p.token_url.as_deref()),
        ];
        for (key, url) in urls {
            let Some(host) = url.and_then(refused_private_host) else {
                continue;
            };
            if destination_allowed(&cfg.guard.allow, &host) {
                continue;
            }
            diag_warn!(
                crate::diagnostics::CONFIG_PROVIDER_DESTINATION_REFUSED,
                "provider '{name}' {key} names the private or loopback host '{host}': with \
                 advanced.block_private_addresses on (the default) the destination guard refuses \
                 every request to it. Add '{host}' to advanced.allow_destinations (busbar \
                 --migrate-config adds the hosts a provider's plane reports), or set \
                 advanced.block_private_addresses: false to admit every private address"
            );
        }
    }
}

fn refused_private_host(url: &str) -> Option<String> {
    let host = busbar_contract::net::url_host(url)?;
    let host = busbar_contract::net::judged_host(&host).ok()?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    (busbar_contract::net::host_is_private_or_loopback(&host)
        && !busbar_contract::net::host_is_cloud_metadata(&host))
    .then_some(host)
}

fn destination_allowed(allow: &[String], host: &str) -> bool {
    let ip = busbar_contract::net::host_ip(host);
    allow.iter().any(|entry| {
        let entry = entry.trim().trim_start_matches('[').trim_end_matches(']');
        let entry = entry
            .strip_suffix('.')
            .unwrap_or(entry)
            .to_ascii_lowercase();
        if entry.eq_ignore_ascii_case(host) {
            return true;
        }
        if let Some(domain) = entry.strip_prefix("*.") {
            let lower = host.to_ascii_lowercase();
            return lower.ends_with(&format!(".{}", domain.to_ascii_lowercase()));
        }
        let Some(ip) = ip else { return false };
        match entry.split_once('/') {
            None => busbar_contract::net::host_ip(&entry) == Some(ip),
            Some((net, bits)) => match (
                busbar_contract::net::host_ip(net.trim_end_matches(']')),
                bits.parse::<u32>(),
            ) {
                (Some(std::net::IpAddr::V4(n)), Ok(b)) if b <= 32 => match ip {
                    std::net::IpAddr::V4(a) => {
                        let mask = u32::MAX.checked_shl(32 - b).unwrap_or(0);
                        u32::from(a) & mask == u32::from(n) & mask
                    }
                    std::net::IpAddr::V6(_) => false,
                },
                (Some(std::net::IpAddr::V6(n)), Ok(b)) if b <= 128 => match ip {
                    std::net::IpAddr::V6(a) => {
                        let mask = u128::MAX.checked_shl(128 - b).unwrap_or(0);
                        u128::from(a) & mask == u128::from(n) & mask
                    }
                    std::net::IpAddr::V4(_) => false,
                },
                _ => false,
            },
        }
    })
}

pub fn metadata_denylist_entries() -> Vec<String> {
    [
        "169.254.0.0/16",
        "100.100.100.200",
        "168.63.129.16",
        "192.0.0.192",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn metadata_enforced_entries() -> Vec<String> {
    let mut entries = metadata_denylist_entries();
    entries.extend(["fd00:ec2::23".to_string(), "fe80::/10".to_string()]);
    entries
}

pub mod deal;

pub(crate) mod secret_refs;
mod undeclared_secret_refs;
#[cfg(test)]
pub(crate) use secret_refs::registry_refusal;
pub(crate) use secret_refs::{keyless_credential_allowed, secret_module, secret_refs};
pub(crate) use undeclared_secret_refs::undeclared_secret_refs;

mod check;
pub use check::{check, no_root_rules, Check, Refusal};

fn validate_providers_with(
    known: &[&str],
    cfg: &RootCfg,
    unset_env_vars: &[String],
    errors: &mut Vec<String>,
) {
    let is_env_placeholder = |v: &str| {
        !v.contains("://")
            && unset_env_vars
                .iter()
                .any(|u| !u.is_empty() && v.contains(u.as_str()))
    };

    for (provider_name, provider_cfg) in &cfg.providers {
        validate_provider_protocol_with(known, provider_name, provider_cfg.dialect(), errors);

        if let Err(refusal) = crate::config::providers::judge_options(provider_name, provider_cfg) {
            errors.push(refusal);
        }

        if let Some(health) = &provider_cfg.health {
            if health.interval_secs == Some(0) {
                errors.push(format!(
                    "provider '{provider_name}' health.interval_secs must be >= 1 (got 0)"
                ));
            }
            if health.timeout_secs == Some(0) {
                errors.push(format!(
                    "provider '{provider_name}' health.timeout_secs must be >= 1 (got 0)"
                ));
            }

            for (field, v) in [
                ("interval_secs", health.interval_secs),
                ("timeout_secs", health.timeout_secs),
            ] {
                if let Some(v) = v.filter(|v| *v > MAX_DURATION_SECS) {
                    errors.push(format!(
                        "provider '{provider_name}' health.{field} ({v}) exceeds the maximum of \
                         {MAX_DURATION_SECS} s (30 years, the async runtime's own 'never' horizon); \
                         a larger duration overflows the clock arithmetic it feeds"
                    ));
                }
            }
        }

        for (code, mapped_class) in provider_cfg.error_map() {
            if busbar_contract::upstream::StatusClass::parse(mapped_class).is_none() {
                errors.push(format!(
                    "provider '{provider_name}' error_map code '{code}': invalid StatusClass '{mapped_class}', must be one of: rate_limit, overloaded, server_error, timeout, network, auth, billing, client_error, context_length"
                ));
            }
        }

        let style = provider_cfg
            .auth
            .as_ref()
            .map(crate::config::ProviderAuth::as_str);
        let style_flags = style.map_or(0, crate::preflight::style_flags);
        let style = style.unwrap_or_default();

        reject_cidr_metadata_entries(
            &format!("provider '{provider_name}' allow_metadata_hosts"),
            &provider_cfg.allow_metadata_hosts,
            errors,
        );
        reject_unmappable_metadata_entries(
            &format!("provider '{provider_name}' allow_metadata_hosts"),
            &provider_cfg.allow_metadata_hosts,
            errors,
        );
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();

        let base_url = &provider_cfg.base_url;
        let host_for_scheme = extract_normalized_host(base_url);
        let host_is_local = host_for_scheme
            .as_deref()
            .map(host_is_private_or_loopback)
            .unwrap_or(false);

        let scheme_ok = is_env_placeholder(base_url)
            || scheme_is(base_url, "https")
            || (host_is_local && scheme_is(base_url, "http"));
        if !scheme_ok {
            let plaintext = scheme_is(base_url, "http");
            let base_url = busbar_kernel_egress::trust::net::redact_userinfo(base_url);
            errors.push(if plaintext {


                format!(
                    "provider '{provider_name}' base_url must use https for a public host (got '{base_url}'); plaintext http is permitted only for a private/loopback local-model upstream"
                )
            } else {
                format!(
                    "provider '{provider_name}' base_url must use http or https (got '{base_url}')"
                )
            });
        } else if let Some(host) = ssrf_blocked_host(
            base_url,
            &allow_overrides,
            cfg.allow_all_metadata,
            &cfg.blocked_metadata_hosts,
        ) {
            let base_url = busbar_kernel_egress::trust::net::redact_userinfo(base_url);
            errors.push(format!(
                "provider '{provider_name}' base_url '{base_url}' targets a blocked cloud-metadata host '{host}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts to unblock it for all providers, or set security.allow_all_metadata: true to disable the guard entirely — and security.blocked_metadata_hosts extends the denylist)"
            ));
        }

        if let Some(path) = &provider_cfg.path {
            if !path.starts_with('/') {
                errors.push(format!(
                    "provider '{provider_name}' path '{path}' must begin with '/': a path override is appended to base_url verbatim, so a path that does not start with '/' fuses into the host (e.g. base_url + '{path}') and can redirect signed traffic to an attacker-controlled host"
                ));
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    let composed = busbar_kernel_egress::trust::net::redact_userinfo(&composed);
                    errors.push(format!(
                        "provider '{provider_name}' base_url+path '{composed}' targets a blocked cloud-metadata host '{host}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)"
                    ));
                }
            }
        }

        if let Some(path_base) = &provider_cfg.path_base {
            if !path_base.starts_with('/') {
                errors.push(format!(
                    "provider '{provider_name}' path_base '{path_base}' must begin with '/': it is appended to base_url verbatim, so a value that does not start with '/' fuses into the host and can redirect signed traffic to an attacker-controlled host"
                ));
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path_base);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    let composed = busbar_kernel_egress::trust::net::redact_userinfo(&composed);
                    errors.push(format!(
                        "provider '{provider_name}' base_url+path_base '{composed}' targets a blocked cloud-metadata host '{host}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)"
                    ));
                }
            }
        }

        if style_flags & busbar_contract::abi::auth::STYLE_ENDPOINT_TOKEN_URL != 0 {
            if provider_cfg.api_key.is_none() {
                errors.push(format!(
                    "provider '{provider_name}' uses auth: {style} but declares \
                     `api_key: none`; that grant mints its token FROM the credential \
                     (`client_id:client_secret`), so there is nothing to declare keyless"
                ));
            }
            if provider_cfg
                .token_url
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(format!(
                    "provider '{provider_name}' uses auth: {style} but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to)"
                ));
            } else if let Some(tu) = &provider_cfg.token_url {
                let host_private = extract_normalized_host(tu)
                    .as_deref()
                    .map(host_is_private_or_loopback)
                    .unwrap_or(false);
                let tu_scheme_ok = is_env_placeholder(tu)
                    || scheme_is(tu, "https")
                    || (host_private && scheme_is(tu, "http"));
                if !tu_scheme_ok {
                    let plaintext = scheme_is(tu, "http");
                    let tu = busbar_kernel_egress::trust::net::redact_userinfo(tu);
                    errors.push(if plaintext {
                        format!(
                            "provider '{provider_name}' token_url must use https for a public host (got '{tu}'); it carries the client secret, so plaintext http is permitted only for a private/loopback token endpoint"
                        )
                    } else {
                        format!(
                            "provider '{provider_name}' token_url must use http or https (got '{tu}')"
                        )
                    });
                } else if let Some(host) = ssrf_blocked_host(
                    tu,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    let tu = busbar_kernel_egress::trust::net::redact_userinfo(tu);
                    errors.push(format!(
                        "provider '{provider_name}' token_url '{tu}' targets a blocked cloud-metadata host '{host}' (the client secret is POSTed there; cloud-metadata/IMDS endpoints are denied — override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)"
                    ));
                }
            }
            if provider_cfg
                .scope
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(format!(
                    "provider '{provider_name}' uses auth: {style} but has no `scope`"
                ));
            }

            let cred = crate::config::secret::resolve_linked_string_at_config(
                &provider_cfg.api_key,
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
            .unwrap_or_default();
            let cred = cred.expose(&crate::seal::lend());
            if !cred.trim().is_empty() {
                let token_url = provider_cfg.token_url.as_deref().unwrap_or_default();
                let params = serde_json::json!({
                    "token_url": busbar_kernel_egress::trust::net::strip_userinfo(token_url),
                    "scope": provider_cfg.scope.clone().unwrap_or_default(),
                });
                for e in outbound_credential_refusals(style, cred, &params) {
                    errors.push(format!(
                        "provider '{provider_name}' {style} credential (from {}) is invalid: {e}",
                        provider_cfg.api_key.describe()
                    ));
                }
            }
        }

        if style_flags & busbar_contract::abi::auth::STYLE_ENDPOINT_FROM_CREDENTIAL != 0 {
            if provider_cfg.api_key.is_none() {
                errors.push(format!(
                    "provider '{provider_name}' uses auth: {style} but declares \
                     `api_key: none`; that grant signs its assertion WITH the credential (the \
                     service-account JSON or key file), so there is nothing to declare keyless"
                ));
            }
            let config_time = busbar_contract::config_time::ConfigScope::config_time();
            let cred = crate::config::secret::resolve_linked_string_at_config(
                &provider_cfg.api_key,
                &config_time,
            )
            .unwrap_or_default();

            let seal = crate::seal::lend();
            let cred = match service_account_json(cred.expose(&seal).clone().into_bytes(), |file| {
                crate::config::secret::SecretResolver::builtins_only()
                    .resolve_at_config(file, &config_time)
                    .map(|held| held.expose(&seal).clone())
            }) {
                Ok(json) => String::from_utf8(json).unwrap_or_default(),
                Err(e) => {
                    errors.push(format!(
                        "provider '{provider_name}' {style} credential (from {}) is invalid: {e}",
                        provider_cfg.api_key.describe()
                    ));
                    String::new()
                }
            };
            if !cred.trim().is_empty() {
                let vetted = service_account_token_uri(&cred).map_or(Ok(()), |uri| {
                    vet_token_uri(
                        &uri,
                        &MetadataPosture {
                            allow_overrides: allow_overrides.clone(),
                            allow_all: cfg.allow_all_metadata,
                            blocked_hosts: cfg.blocked_metadata_hosts.clone(),
                        },
                    )
                });
                let refusals = match vetted {
                    Err(e) => vec![e],
                    Ok(()) => {
                        let mut params = serde_json::Map::new();
                        if let Some(scope) = &provider_cfg.scope {
                            params.insert("scope".into(), serde_json::Value::String(scope.clone()));
                        }
                        outbound_credential_refusals(
                            style,
                            &cred,
                            &serde_json::Value::Object(params),
                        )
                    }
                };
                for e in refusals {
                    errors.push(format!(
                        "provider '{provider_name}' {style} credential (from {}) is invalid: {e}",
                        provider_cfg.api_key.describe()
                    ));
                }
            }
        }
    }
}

/// ONE PROVIDER'S METADATA POSTURE, owned: the hosts its destinations may reach past the
/// cloud-metadata denylist (its own `allow_metadata_hosts` and the global
/// `security.allow_metadata_hosts`, the union every destination check here builds), the nuclear
/// `security.allow_all_metadata`, and the operator's extra `security.blocked_metadata_hosts`. The
/// composition root carries it to the seal, where a resolved credential's own token endpoint is
/// judged under it ([`vet_token_uri`]), as 1.5.5's boot judged it (`main.rs`, v1.5.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataPosture {
    /// The provider's allow-overrides, then the global ones.
    pub allow_overrides: Vec<String>,
    /// `security.allow_all_metadata`.
    pub allow_all: bool,
    /// `security.blocked_metadata_hosts`.
    pub blocked_hosts: Vec<String>,
}

impl MetadataPosture {
    #[must_use]
    pub fn global(cfg: &RootCfg) -> Self {
        Self {
            allow_overrides: cfg.allow_metadata_hosts.clone(),
            allow_all: cfg.allow_all_metadata,
            blocked_hosts: cfg.blocked_metadata_hosts.clone(),
        }
    }

    #[must_use]
    pub fn for_provider(&self, provider: &crate::config::ResolvedProvider) -> Self {
        Self {
            allow_overrides: provider
                .allow_metadata_hosts
                .iter()
                .chain(self.allow_overrides.iter())
                .cloned()
                .collect(),
            allow_all: self.allow_all,
            blocked_hosts: self.blocked_hosts.clone(),
        }
    }
}

fn outbound_credential_refusals(
    style: &str,
    credential: &str,
    params: &serde_json::Value,
) -> Vec<String> {
    let Some(axis) = crate::preflight::linked_auth_axis() else {
        return Vec::new();
    };
    credential_refusals_from(axis.as_ref(), style, credential, params)
}

fn credential_refusals_from(
    axis: &dyn busbar_contract::auth_calls::AuthAxis,
    style: &str,
    credential: &str,
    params: &serde_json::Value,
) -> Vec<String> {
    let refusals = axis
        .check_outbound(style, credential.as_bytes(), params)
        .unwrap_or_else(|error| vec![error]);
    let needles = credential_needles(credential);
    refusals
        .into_iter()
        .map(|text| redact_credential(text, &needles))
        .collect()
}

const REDACTED_CREDENTIAL: &str = "[redacted]";

const MIN_NEEDLE: usize = 4;

fn credential_needles(credential: &str) -> Vec<String> {
    use base64::Engine as _;
    let mut needles = vec![credential.to_string(), credential.trim().to_string()];
    if let Some((_, secret)) = credential.trim().split_once(':') {
        needles.push(secret.to_string());
    }
    if let Ok(serde_json::Value::Object(account)) = serde_json::from_str(credential) {
        if let Some(serde_json::Value::String(key)) = account.get("private_key") {
            needles.push(key.clone());
            if let Ok(quoted) = serde_json::to_string(key) {
                needles.push(quoted.trim_matches('"').to_string());
            }
        }
    }
    for raw in [credential, credential.trim()] {
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            needles.push(engine.encode(raw.as_bytes()));
        }
    }
    needles.retain(|n| n.len() >= MIN_NEEDLE);
    needles.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    needles.dedup();
    needles
}

fn redact_credential(mut text: String, needles: &[String]) -> String {
    for needle in needles {
        if text.contains(needle.as_str()) {
            text = text.replace(needle.as_str(), REDACTED_CREDENTIAL);
        }
    }
    text
}

pub fn service_account_json(
    credential: Vec<u8>,
    read_file: impl FnOnce(&busbar_contract::secret_ref::SecretRef) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let named = match std::str::from_utf8(&credential) {
        Ok(text) if !text.trim_start().starts_with('{') && !text.trim().is_empty() => {
            text.trim().to_string()
        }
        _ => return Ok(credential),
    };
    let file = busbar_contract::secret_ref::SecretRef::file(named.clone());
    read_file(&file).map_err(|e| {
        let why = e.split_once(" cannot resolve: ").map_or_else(
            || e.replace(&named, "<key file>"),
            |(_, why)| why.to_string(),
        );
        format!("could not read service-account key file named by this lane's credential: {why}")
    })
}

pub fn service_account_token_uri(credential: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct TokenUri {
        #[allow(dead_code)]
        client_email: serde::de::IgnoredAny,
        #[allow(dead_code)]
        private_key: serde::de::IgnoredAny,
        token_uri: Option<String>,
    }
    let parsed: TokenUri = serde_json::from_str(credential).map_err(|e| e.to_string())?;
    Ok(parsed
        .token_uri
        .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string()))
}

pub fn vet_token_uri(token_uri: &str, posture: &MetadataPosture) -> Result<(), String> {
    use busbar_contract::net::{extract_normalized_host, host_is_private_or_loopback, scheme_is};
    let host_private = extract_normalized_host(token_uri)
        .as_deref()
        .map(host_is_private_or_loopback)
        .unwrap_or(false);
    if !(scheme_is(token_uri, "https") || (host_private && scheme_is(token_uri, "http"))) {
        let token_uri = busbar_kernel_egress::trust::net::redact_userinfo(token_uri);
        return Err(format!(
            "service-account token_uri must use https for a public host (got '{token_uri}'); it receives the signed JWT assertion, so plaintext http is permitted only for a private/loopback endpoint"
        ));
    }
    if let Some(host) = ssrf_blocked_host(
        token_uri,
        &posture.allow_overrides,
        posture.allow_all,
        &posture.blocked_hosts,
    ) {
        let token_uri = busbar_kernel_egress::trust::net::redact_userinfo(token_uri);
        return Err(format!(
            "service-account token_uri '{token_uri}' targets a blocked cloud-metadata host '{host}' (the signed assertion would be POSTed there; cloud-metadata/IMDS endpoints are denied — override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)"
        ));
    }
    Ok(())
}

fn validate_provider_protocol_with(
    known: &[&str],
    provider_name: &str,
    protocol: &str,
    errors: &mut Vec<String>,
) {
    if known.is_empty() {
        errors.push(format!(
            "provider '{provider_name}' names protocol '{protocol}', but this build has NO protocol \
             with a wire codec compiled in, so no provider lane can be served"
        ));
    } else if !known.contains(&protocol) {
        errors.push(format!(
            "provider '{}' has unknown protocol '{}': must be one of: {}",
            provider_name,
            protocol,
            known.join(", ")
        ));
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/store_required_tests.rs"]
mod store_required_tests;

#[cfg(test)]
#[path = "tests/secret_shorthand_declared_tests.rs"]
mod secret_shorthand_declared_tests;

#[cfg(test)]
#[path = "tests/credential_echo_tests.rs"]
mod credential_echo_tests;
