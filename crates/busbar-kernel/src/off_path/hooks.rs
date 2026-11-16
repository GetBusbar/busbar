// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `hooks`' off-path code: the hook environment and every hook resolver (pool, global and
//! container gates, rewrites and taps, their on_error chains), run once per boot or reload; the
//! admin configure, status and schema reads; the gate resolution cache those resolvers share. The
//! request path only calls the policies these resolve.

use crate::hooks::{
    FallbackHook, HookHttp, ResolvedPolicy, RewriteOnError, RoutingPolicy, Signal, TapEntry,
    SECTION_SCOPE,
};
use busbar_kernel::config::plane_sections::attach_list;
use std::sync::Arc;

pub(crate) fn policy_timeout(timeout_ms: u64) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        crate::limits::default_policy_timeout_ms()
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms)
}

pub(crate) fn same_call_inputs(
    opened_module: &str,
    opened_settings: &busbar_contract::plugin_settings::Settings,
    opened_budget: std::time::Duration,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
    effective_budget: impl FnOnce() -> std::time::Duration,
) -> bool {
    opened_module == module && opened_settings == settings && opened_budget == effective_budget()
}

pub(crate) fn same_resolved_inputs(
    opened_module: &str,
    opened_settings: &ResolvedSettings,
    opened_budget: std::time::Duration,
    module: &str,
    settings: &ResolvedSettings,
    effective_budget: impl FnOnce() -> std::time::Duration,
) -> bool {
    if opened_module != module || opened_budget != effective_budget() {
        return false;
    }
    let (Ok(opened), Ok(current)) = (opened_settings.encode(), settings.encode()) else {
        return false;
    };
    let seal = crate::seal::lend();
    opened.expose(&seal) == current.expose(&seal)
}

/// The plugin-resolution environment threaded through every hook-transport builder: the validated
/// plugin registry and the root's hook axis over it (a hook's `plugin:` ref opens through the axis,
/// called as a [`plugin::HookPolicy`], whose replies run through the kernel's own fail-closed `wire`
/// normalizers). Cheap to clone (`Arc`-backed).
#[derive(Clone)]
pub struct HookEnv {
    pub registry: std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
    /// THE HOOK AXIS over `registry`, as the composition root built it (`RootInstall::hook_axis`):
    /// every `kind: hook` row, compiled in or dropped in, opened on the hook kind's ABI over the
    /// process's one dispatcher. `None` = this build installs no axis: no hook opens.
    pub(crate) axis: Option<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>>,
    pub(crate) route_calls: Arc<foldhash::HashMap<String, RouteCalls>>,
    /// Declared paths read once outside cache admission. Reading a linked row's Statement may
    /// invoke its door, so the cache key must consult this snapshot instead of the registry.
    pub(crate) resolution_paths: Arc<resolution::Paths>,
    /// The secret resolver turns typed hook references, such as a `accessToken`, into their raw values before settings cross the ABI at open/configure. It is the same fail-closed resolver shared with store and auth opens, held through the neutral [`busbar_contract::secret::SecretResolve`] trait rather than the concrete engine resolver. Wiring supplies the identical resolver instance; only the static type at the hook boundary is narrowed.
    ///
    ///
    ///
    ///
    ///
    ///
    pub secret_resolver: std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
    /// Names of hooks that have already emitted the loud [`hook_inert_gate_banner`] THIS build. A
    /// gate named in several pools' `hooks:` lists (and/or `global_hooks`) resolves once per
    /// reference — `resolve_pool_rewrites` runs once per pool, `resolve_rewrite_hooks` once for
    /// globals — so without this guard the same inert-gate banner would print once per reference,
    /// unlike `open_relay_banner`/`inert_durable_keys_banner`, which fire exactly once. `Arc`-shared
    /// so every clone of this `HookEnv` (the resolvers each take `&HookEnv`, and the offloaded
    /// control-plane reads clone it onto a blocking thread) sees the same set; fresh and empty every
    /// `HookEnv::new`, i.e. every boot/reload, so a still-inert hook re-banners on the NEXT
    /// boot/reload rather than going silent forever.
    pub(crate) banner_seen: std::sync::Arc<std::sync::Mutex<foldhash::HashSet<String>>>,
}

impl HookEnv {
    pub fn new(
        registry: std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
    ) -> Result<Self, String> {
        let axis = match crate::preflight::root_rows().hook_axis {
            Some(build) => Some(build(&registry)?),
            None => None,
        };
        let resolution_paths = resolution::Paths::new(&registry);
        Ok(HookEnv {
            registry,
            axis,
            route_calls: Arc::default(),
            resolution_paths,
            secret_resolver,
            banner_seen: std::sync::Arc::default(),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_axis(
        registry: std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        axis: std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>,
        secret_resolver: std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
    ) -> Self {
        let resolution_paths = resolution::Paths::new(&registry);
        HookEnv {
            registry,
            axis: Some(axis),
            route_calls: Arc::default(),
            resolution_paths,
            secret_resolver,
            banner_seen: std::sync::Arc::default(),
        }
    }

    pub(crate) fn knows(&self, module: &str) -> bool {
        self.registry.resolve(module).is_some()
            || self.axis.as_ref().is_some_and(|a| a.linked(module))
    }

    pub(crate) fn open(
        &self,
        module: &str,
        settings: &ResolvedSettings,
        name: &str,
        timeout_ms: u64,
        signals: &[Signal],
        child: Option<&crate::hook_child::Grant>,
    ) -> Result<Arc<dyn RoutingPolicy>, String> {
        if let Some(opened) = self.route_calls.get(name).filter(|opened| {
            same_resolved_inputs(
                &opened.module,
                &opened.resolved,
                opened.budget,
                module,
                settings,
                || policy_timeout(timeout_ms),
            )
        }) {
            return Ok(crate::plane_driver::hooks::policy::HookPolicy::policy(
                opened.calls.clone(),
                name,
                signals,
                child,
            ));
        }
        let axis = self
            .axis
            .as_ref()
            .ok_or_else(|| format!("no `kind: hook` plugin answers to '{module}'"))?;
        let calls = axis.open(module, name, settings, policy_timeout(timeout_ms))?;
        Ok(crate::plane_driver::hooks::policy::HookPolicy::policy(
            calls, name, signals, child,
        ))
    }

    pub fn route_decls(
        &mut self,
        hooks: &crate::config::hooks::HookRegistry,
    ) -> Result<Vec<crate::plugin_routes::RouteDecl>, String> {
        let Some(axis) = self.axis.as_ref() else {
            return Ok(Vec::new());
        };
        let mut names: Vec<_> = hooks.keys().collect();
        names.sort();
        let mut calls = foldhash::HashMap::default();
        let mut declarations = Vec::new();
        for name in names {
            let hook = &hooks[name];
            let resolved = self.resolve_hook_settings(&hook.plugin, &hook.settings)?;
            let routes = axis.routes(&hook.plugin, name, &resolved)?;
            if routes.is_empty() {
                continue;
            }
            let budget = policy_timeout(hook.timeout_ms);
            let opened = match retained_route(&self.route_calls, name, |opened| {
                same_resolved_inputs(
                    &opened.module,
                    &opened.resolved,
                    opened.budget,
                    &hook.plugin,
                    &resolved,
                    || budget,
                )
            })
            .filter(|opened| opened.calls.routes() == routes.as_slice())
            {
                Some(opened) => opened.calls.clone(),
                None => axis.open(&hook.plugin, name, &resolved, budget)?,
            };
            if opened.routes() != routes.as_slice() {
                return Err(format!(
                    "hook '{name}' route declarations changed while opening"
                ));
            }
            let dispatch: Arc<dyn crate::plugin_routes::PluginHttpDispatch> = Arc::new(HookHttp {
                calls: opened.clone(),
                budget,
            });
            for route in opened.routes() {
                declarations.push(crate::plugin_routes::RouteDecl {
                    owner: name.clone(),
                    source_instance: name.clone(),
                    dispatch_available: true,
                    kind: crate::plugin_routes::RouteKind::Hook,
                    route: route.clone(),
                    scrape: false,
                    persistent: false,
                    dispatch: dispatch.clone(),
                });
            }
            calls.insert(
                name.clone(),
                RouteCalls {
                    module: hook.plugin.clone(),
                    definition: hook.settings.clone(),
                    resolved,
                    budget,
                    calls: opened,
                },
            );
        }
        self.route_calls = Arc::new(calls);
        Ok(declarations)
    }

    pub(crate) fn resolve_hook_settings(
        &self,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
    ) -> Result<ResolvedSettings, String> {
        crate::config::secret::resolve_settings(
            settings,
            &self.registry.secret_slots(module),
            &self.registry.reference_slots(module),
            module,
            self.secret_resolver.as_ref(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
    }

    pub fn preresolve_hook_secrets(
        &self,
        hooks: &crate::config::hooks::HookRegistry,
    ) -> Result<(), String> {
        for (name, hook) in hooks {
            self.resolve_hook_settings(&hook.plugin, &hook.settings)
                .map_err(|e| format!("hook '{name}' settings: {e}"))?;
        }
        Ok(())
    }

    pub fn preopen_gate_hooks(
        &self,
        hooks: &crate::config::hooks::HookRegistry,
    ) -> Result<(), String> {
        preopen_definitions(
            hooks,
            |module| self.knows(module),
            |_, hook| self.resolve_hook_settings(&hook.plugin, &hook.settings),
            |name, hook, resolved| {
                self.open(
                    &hook.plugin,
                    &resolved,
                    name,
                    hook.timeout_ms,
                    &hook.signals,
                    hook.child_dispatch.as_ref(),
                )
                .map(|_| ())
            },
        )
    }
}

pub(crate) fn preopen_definitions<T>(
    hooks: &crate::config::hooks::HookRegistry,
    mut knows: impl FnMut(&str) -> bool,
    mut resolve: impl FnMut(&str, &crate::config::HookCfg) -> Result<T, String>,
    mut open: impl FnMut(&str, &crate::config::HookCfg, T) -> Result<(), String>,
) -> Result<(), String> {
    for (name, hook) in hooks {
        if hook.kind != crate::config::HookKind::Gate || !knows(&hook.plugin) {
            continue;
        }
        let resolved = resolve(name, hook).map_err(|e| format!("hook '{name}' settings: {e}"))?;
        open(name, hook, resolved).map_err(|e| {
            format!(
                "gate hook '{name}' (plugin '{}') failed to open; refusing to boot/reload \
             with a silently-absent admission gate (fail-closed): {e}",
                hook.plugin
            )
        })?;
    }
    Ok(())
}

pub(crate) fn retained_route<'a, T>(
    routes: &'a foldhash::HashMap<String, T>,
    name: &str,
    matches: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    routes.get(name).filter(|retained| matches(*retained))
}

pub(crate) struct RouteCalls {
    module: String,
    definition: busbar_contract::plugin_settings::Settings,
    resolved: ResolvedSettings,
    budget: std::time::Duration,
    calls: Arc<dyn busbar_contract::hook_calls::HookCalls>,
}

pub fn resolve_policy(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    let name = cfg.policy.native_name()?;

    let (policy, timeout) = crate::preflight::builtin_ranking(name)?;
    Some(ranked_policy(policy, timeout))
}

pub(crate) fn ranked_policy(
    policy: Arc<dyn RoutingPolicy>,
    timeout: std::time::Duration,
) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: crate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout,

        send_prompt: false,
        send_user: false,

        on_empty: crate::config::PolicyOnError::Reject,
    }
}

pub fn default_hook_name(hooks: &crate::config::hooks::HookRegistry) -> Option<&str> {
    hooks
        .iter()
        .find(|(_, h)| h.default)
        .map(|(name, _)| name.as_str())
}

pub fn resolve_pool_ordering(
    cfg: &crate::config::PoolCfg,
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    default_hook: Option<&str>,
    settings_version: u64,
) -> Option<ResolvedPolicy> {
    try_resolve_pool_ordering(cfg, hooks, env, default_hook, settings_version)
        .ok()
        .flatten()
}

pub fn try_resolve_pool_ordering(
    cfg: &crate::config::PoolCfg,
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    default_hook: Option<&str>,
    settings_version: u64,
) -> Result<Option<ResolvedPolicy>, String> {
    if let Some((name, hook)) = inherited_ordering(cfg, hooks, default_hook) {
        return Ok(resolve_gate_transport(
            name,
            hook,
            hooks,
            env,
            settings_version,
        ));
    }
    let Some(name) = cfg.policy.native_name() else {
        return Ok(None);
    };
    let axis = env
        .axis
        .as_ref()
        .ok_or_else(|| format!("ranking strategy '{name}' has no hook axis"))?;
    let (policy, timeout) = crate::preflight::ranking_on_axis(axis.as_ref(), name)?;
    Ok(Some(ranked_policy(policy, timeout)))
}

pub(crate) fn inherited_ordering<'a>(
    cfg: &crate::config::PoolCfg,
    hooks: &'a crate::config::hooks::HookRegistry,
    default_hook: Option<&'a str>,
) -> Option<(&'a str, &'a crate::config::HookCfg)> {
    if cfg.base_named {
        return None;
    }
    let name = default_hook?;
    let hook = hooks.get(name)?;
    if hook.kind == crate::config::HookKind::Gate && !hook.prompt.can_rewrite() {
        return Some((name, hook));
    }
    tracing::warn!(hook = %name,
        "`default: true` hook is not a decision gate; ignored as the base ordering \
         (the compiled-in weighted backstop applies)");
    None
}

pub fn resolve_pool_gates(
    cfg: &crate::config::PoolCfg,
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(u16, ResolvedPolicy)> {
    let mut ranked: Vec<(u16, ResolvedPolicy)> = decision_definitions(hooks, &cfg.gates)
        .into_iter()
        .filter_map(|(name, hook)| {
            resolve_gate_transport(name, hook, hooks, env, settings_version)
                .map(|rp| (hook.priority, rp))
        })
        .collect();

    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

pub fn resolve_pool_rewrites(
    cfg: &crate::config::PoolCfg,
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for (name, hook) in rewrite_definitions(hooks, &cfg.gates, |name, hook| {
        admits_rewrite(name, hook, env)
    }) {
        if let Some(ResolvedPolicy::Policy {
            policy,
            timeout,
            on_error,
            on_error_chain,
            ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((
                hook.priority,
                timeout,
                with_rewrite_on_error(policy, on_error, on_error_chain),
            ));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

pub(crate) fn with_rewrite_on_error(
    policy: Arc<dyn RoutingPolicy>,
    on_error: crate::config::PolicyOnError,
    on_error_chain: Vec<FallbackHook>,
) -> Arc<dyn RoutingPolicy> {
    Arc::new(RewriteOnError {
        inner: policy,
        on_error,
        on_error_chain,
    })
}

pub(crate) fn resolve_gate_transport(
    name: &str,
    hook: &crate::config::HookCfg,
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> Option<ResolvedPolicy> {
    let (policy, _resolved) = gate_transport_named(name, hook, env, settings_version)?;
    let (on_error_chain, on_error) = resolve_on_error_chain(hook, hooks, env, settings_version);
    let (send_prompt, send_user) = projection_grants(name, hook, env);
    Some(ResolvedPolicy::Policy {
        policy,
        on_error,
        on_error_chain,
        timeout: policy_timeout(hook.timeout_ms),
        send_prompt,
        send_user,
        on_empty: gate_on_empty(hook),
    })
}

pub(crate) fn hook_inert_gate_banner(
    name: &str,
    plugin: &str,
    kind: crate::config::HookKind,
    needs_prompt: busbar_contract::plugin_rows::NeedLevel,
) -> Option<String> {
    if kind != crate::config::HookKind::Gate {
        return None;
    }
    Some(format!(
        "hook '{name}' (plugin '{plugin}') grants `prompt: rw` but its signed manifest only \
         declares `needs.prompt: {needs_prompt:?}` — this hook is INERT wherever it is named \
         directly (as a pool `hook:`/`hooks:` entry or in `global_hooks`): it is excluded from the \
         decision-gate chain by design (a `prompt: rw` grant is never promoted into a decision gate \
         it never asked for) AND fails the rewrite chain's effective-grant check (the manifest never \
         declared a rewrite need). The plugin still opens successfully at boot/reload and the admin \
         API still reports it registered with `prompt: \"rw\"`, so nothing else will tell you this. \
         Fix: lower the hook's `prompt:` grant to match the manifest (`ro` or omit), or use a plugin \
         build whose manifest declares `needs: {{ prompt: rw }}`."
    ))
}

#[derive(Clone, Copy)]
pub(crate) struct Needs {
    pub(crate) prompt: busbar_contract::plugin_rows::NeedLevel,
    pub(crate) user: busbar_contract::plugin_rows::NeedLevel,
}

impl Needs {
    fn declares_any(&self) -> bool {
        self.prompt.wants_read() || self.user.wants_read()
    }
}

pub(crate) fn effective_access(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> (crate::config::PromptAccess, crate::config::UserAccess) {
    let Some(p) = env.registry.resolve(&hook.plugin) else {
        return (hook.prompt, hook.user);
    };
    access_from_intent(
        name,
        hook,
        Needs {
            prompt: p.needs_prompt,
            user: p.needs_user,
        },
        &env.banner_seen,
    )
}

pub(crate) fn access_from_intent(
    name: &str,
    hook: &crate::config::HookCfg,
    needs: Needs,
    banner_seen: &std::sync::Mutex<foldhash::HashSet<String>>,
) -> (crate::config::PromptAccess, crate::config::UserAccess) {
    use crate::config::{PromptAccess, UserAccess};
    use busbar_contract::plugin_rows::NeedLevel;

    let grant_prompt = hook.prompt;
    let grant_user = hook.user;

    let eff_prompt = match (grant_prompt, needs.prompt) {
        (PromptAccess::No, _) | (_, NeedLevel::No) => PromptAccess::No,
        (PromptAccess::Rw, NeedLevel::Rw) => PromptAccess::Rw,
        _ => PromptAccess::Ro,
    };
    let eff_user = match (grant_user, needs.user) {
        (UserAccess::No, _) | (_, NeedLevel::No) => UserAccess::No,
        _ => UserAccess::Ro,
    };

    if grant_prompt.sends_prompt() && !needs.prompt.wants_read() {
        tracing::warn!(
            hook = %name, plugin = %hook.plugin,
            "hook grants `prompt` but the plugin manifest declares no prompt need — no prompt \
             content will be sent (grant is inert)"
        );
    }

    if grant_prompt.can_rewrite() && !needs.prompt.wants_rewrite() {
        match hook_inert_gate_banner(name, &hook.plugin, hook.kind, needs.prompt) {
            Some(banner) if first_banner(banner_seen, name) => {
                eprintln!("[error] {banner}");
                tracing::error!("{banner}");
            }
            Some(_) => {}
            None => {
                tracing::warn!(
                    hook = %name, plugin = %hook.plugin,
                    needs_prompt = ?needs.prompt,
                    "hook grants `prompt: rw` but the plugin manifest declares no prompt REWRITE \
                     need — the hook is NOT admitted to the rewrite chain (grant is inert)"
                );
            }
        }
    }
    if grant_user.sends_user() && !needs.user.wants_read() {
        tracing::warn!(
            hook = %name, plugin = %hook.plugin,
            "hook grants `user` but the plugin manifest declares no user need — no identity will \
             be sent (grant is inert)"
        );
    }

    if needs.declares_any() {
        tracing::info!(
            hook = %name, plugin = %hook.plugin,
            needs_prompt = ?needs.prompt, needs_user = ?needs.user,
            send_prompt = eff_prompt.sends_prompt(), send_user = eff_user.sends_user(),
            "hook plugin declared content intent"
        );
    }
    (eff_prompt, eff_user)
}

/// Whether `name`'s inert-gate banner has not printed yet this boot or reload (and now records it).
pub(crate) fn first_banner(
    banner_seen: &std::sync::Mutex<foldhash::HashSet<String>>,
    name: &str,
) -> bool {
    let mut seen = banner_seen.lock().unwrap_or_else(|p| p.into_inner());
    if seen.contains(name) {
        return false;
    }
    let name = name.to_string();
    seen.insert(name)
}

pub(crate) fn projection_grants(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> (bool, bool) {
    let (prompt, user) = effective_access(name, hook, env);
    (prompt.sends_prompt(), user.sends_user())
}

pub(crate) fn decision_definitions<'a>(
    hooks: &'a crate::config::hooks::HookRegistry,
    names: &'a [String],
) -> Vec<(&'a str, &'a crate::config::HookCfg)> {
    names
        .iter()
        .filter_map(|name| {
            let hook = hooks.get(name)?;
            (hook.kind == crate::config::HookKind::Gate && !hook.prompt.can_rewrite())
                .then_some((name.as_str(), hook))
        })
        .collect()
}

pub(crate) fn tap_definitions<'a>(
    hooks: &'a crate::config::hooks::HookRegistry,
    names: &'a [String],
    stage: crate::config::HookStage,
) -> Vec<(&'a str, &'a crate::config::HookCfg)> {
    names
        .iter()
        .filter_map(|name| {
            let hook = hooks.get(name)?;
            (hook.kind == crate::config::HookKind::Tap && hook.fires_at_stage(stage))
                .then_some((name.as_str(), hook))
        })
        .collect()
}

pub(crate) fn rewrite_definitions<'a>(
    hooks: &'a crate::config::hooks::HookRegistry,
    names: &'a [String],
    mut admitted: impl FnMut(&str, &crate::config::HookCfg) -> bool,
) -> Vec<(&'a str, &'a crate::config::HookCfg)> {
    names
        .iter()
        .filter_map(|name| {
            let hook = hooks.get(name)?;
            (hook.kind == crate::config::HookKind::Gate && admitted(name, hook))
                .then_some((name.as_str(), hook))
        })
        .collect()
}

pub(crate) fn admits_rewrite(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> bool {
    effective_access(name, hook, env).0.can_rewrite()
}

pub(crate) fn gate_transport_named(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    _settings_version: u64,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    if let Some(opened) = env.route_calls.get(name).filter(|opened| {
        same_call_inputs(
            &opened.module,
            &opened.definition,
            opened.budget,
            &hook.plugin,
            &hook.settings,
            || policy_timeout(hook.timeout_ms),
        )
    }) {
        return Some((
            crate::plane_driver::hooks::policy::HookPolicy::policy(
                opened.calls.clone(),
                name,
                &hook.signals,
                hook.child_dispatch.as_ref(),
            ),
            opened.resolved.clone(),
        ));
    }

    let Some(key) = resolution::key(name, hook, env) else {
        return gate_transport_uncached(name, hook, env);
    };
    let claim = match resolution::admit(key, &env.registry) {
        resolution::Admission::Published(hit) => return Some(hit),
        resolution::Admission::Claim(claim) => claim,
    };
    let out = gate_transport_uncached(name, hook, env);
    if let Some(v) = out.as_ref() {
        claim.publish(v.clone());
    }
    out
}

pub(crate) fn gate_transport_uncached(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    open_resolved(
        name,
        hook,
        env.resolve_hook_settings(&hook.plugin, &hook.settings),
        |resolved| {
            env.open(
                &hook.plugin,
                resolved,
                name,
                hook.timeout_ms,
                &hook.signals,
                hook.child_dispatch.as_ref(),
            )
        },
    )
}

pub(crate) fn open_resolved<T>(
    name: &str,
    hook: &crate::config::HookCfg,
    settings: Result<ResolvedSettings, String>,
    open: impl FnOnce(&ResolvedSettings) -> Result<T, String>,
) -> Option<(T, ResolvedSettings)> {
    let resolved = match settings {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                hook = %name, plugin = %hook.plugin, error = %e,
                "hook settings did not resolve; gate treated as absent (should have been caught by \
                 the pre-resolve pass at boot/reload)"
            );
            return None;
        }
    };
    match open(&resolved) {
        Ok(policy) => Some((policy, resolved)),
        Err(e) => {
            tracing::warn!(
                hook = %name, plugin = %hook.plugin, error = %e,
                "hook plugin failed to load; gate treated as absent (fail-open to the request)"
            );
            None
        }
    }
}

pub(crate) type ResolvedSettings = crate::config::secret::ResolvedSettings;

pub(crate) type Resolved = (Arc<dyn RoutingPolicy>, ResolvedSettings);

pub(crate) mod resolution {
    use super::Resolved;
    use foldhash::HashMap;
    use std::sync::{Condvar, Mutex, OnceLock};

    const CAP: usize = 128;

    pub(crate) struct Paths {
        registry: std::sync::Weak<dyn busbar_contract::plugin_rows::PluginRows>,
        modules: HashMap<String, Vec<String>>,
    }

    impl Paths {
        pub(crate) fn matches(
            &self,
            registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        ) -> bool {
            std::sync::Weak::ptr_eq(&self.registry, &std::sync::Arc::downgrade(registry))
        }

        pub(crate) fn new(
            registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        ) -> std::sync::Arc<Self> {
            let mut modules = HashMap::default();
            for row in registry.loadable().into_iter().chain(registry.linked()) {
                if row.kind != busbar_contract::abi::mechanism::kind::HOOK {
                    continue;
                }
                let mut paths = registry.secret_slots(&row.name);
                paths.extend(registry.reference_slots(&row.name));
                for name in [row.name, row.key, row.alias] {
                    modules.insert(name, paths.clone());
                }
            }
            std::sync::Arc::new(Self {
                registry: std::sync::Arc::downgrade(registry),
                modules,
            })
        }
    }

    struct Entry {
        seq: u64,

        in_flight: bool,
        value: Option<Resolved>,

        registry: std::sync::Weak<dyn busbar_contract::plugin_rows::PluginRows>,
    }

    #[derive(Default)]
    struct Inner {
        entries: HashMap<u64, Entry>,
        seq: u64,
    }

    fn state() -> &'static (Mutex<Inner>, Condvar) {
        static STATE: OnceLock<(Mutex<Inner>, Condvar)> = OnceLock::new();
        STATE.get_or_init(|| (Mutex::new(Inner::default()), Condvar::new()))
    }

    pub(crate) fn key(
        name: &str,
        hook: &crate::config::HookCfg,
        env: &super::HookEnv,
    ) -> Option<u64> {
        if !env.resolution_paths.matches(&env.registry) {
            return None;
        }

        let paths = env.resolution_paths.modules.get(&hook.plugin)?;
        let none = busbar_contract::secret_ref::Sugars::default();
        key_for_settings(
            std::sync::Arc::as_ptr(&env.registry) as *const u8 as usize,
            name,
            hook,
            paths,
            env.secret_resolver.sources().unwrap_or(&none),
        )
    }

    /// `sources`: the shorthand of the generation the hook's settings were written in (its
    /// resolver's, SECRET-SHORTHAND-BOOT §3.4).
    pub(crate) fn key_for_settings(
        registry: usize,
        name: &str,
        hook: &crate::config::HookCfg,
        paths: &[String],
        sources: &busbar_contract::secret_ref::Sugars,
    ) -> Option<u64> {
        use std::hash::{Hash as _, Hasher as _};
        if hook
            .settings
            .undeclared_reference(&[], sources)
            .ok()
            .flatten()
            .is_some()
            || !hook
                .settings
                .reference_modules(paths, sources)
                .ok()?
                .is_empty()
        {
            return None;
        }
        let encoded = hook.settings.encode().ok()?;
        let seal = crate::seal::lend();
        let settings = std::str::from_utf8(encoded.expose(&seal)).ok()?;
        let mut h = std::hash::BuildHasher::build_hasher(&foldhash::fast::FixedState::default());

        registry.hash(&mut h);
        name.hash(&mut h);
        hook.plugin.hash(&mut h);
        super::policy_timeout(hook.timeout_ms).hash(&mut h);
        settings.hash(&mut h);
        hook.signals.hash(&mut h);
        busbar_contract::json::to_writer(HashWriter(&mut h), &hook.child_dispatch).ok()?;
        Some(h.finish())
    }

    /// Feeds serialized bytes straight into a hasher, so a key never materializes the encoding.
    struct HashWriter<'a, H>(&'a mut H);

    impl<H: std::hash::Hasher> std::io::Write for HashWriter<'_, H> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(crate) enum Admission {
        Published(Resolved),
        Claim(Claim),
    }

    pub(crate) struct Claim {
        key: u64,
        published: bool,
    }

    impl Claim {
        pub(crate) fn publish(mut self, value: Resolved) {
            let (lock, cv) = state();
            {
                let mut inner = lock.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(e) = inner.entries.get_mut(&self.key) {
                    e.value = Some(value);
                }
            }
            self.published = true;
            cv.notify_all();
        }
    }

    impl Drop for Claim {
        fn drop(&mut self) {
            let (lock, cv) = state();
            let _evicted = {
                let mut inner = lock.lock().unwrap_or_else(|p| p.into_inner());
                let unpublished = match inner.entries.get_mut(&self.key) {
                    Some(e) => {
                        e.in_flight = false;
                        e.value.is_none()
                    }
                    None => false,
                };
                if unpublished {
                    inner.entries.remove(&self.key);
                }
                evict_over_cap(&mut inner)
            };
            cv.notify_all();
        }
    }

    pub(crate) fn admit(
        key: u64,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
    ) -> Admission {
        let (lock, cv) = state();
        let mut inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match inner.entries.get(&key) {
                Some(e) if e.value.is_some() => {
                    let hit = e.value.clone().expect("checked is_some");
                    return Admission::Published(hit);
                }
                Some(e) if e.in_flight => {
                    inner = cv.wait(inner).unwrap_or_else(|p| p.into_inner());
                }
                _ => {
                    inner.seq += 1;
                    let seq = inner.seq;
                    inner.entries.insert(
                        key,
                        Entry {
                            seq,
                            in_flight: true,
                            value: None,
                            registry: std::sync::Arc::downgrade(registry),
                        },
                    );
                    return Admission::Claim(Claim {
                        key,
                        published: false,
                    });
                }
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn published(key: u64) -> bool {
        let (lock, _) = state();
        let inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.get(&key).is_some_and(|e| e.value.is_some())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn in_flight(key: u64) -> bool {
        let (lock, _) = state();
        let inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.get(&key).is_some_and(|e| e.in_flight)
    }

    fn evict_over_cap(inner: &mut Inner) -> Vec<Entry> {
        let mut evicted = Vec::new();
        let dead: Vec<u64> = inner
            .entries
            .iter()
            .filter(|(_, e)| !e.in_flight && e.registry.strong_count() == 0)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            evicted.extend(inner.entries.remove(&k));
        }
        while inner.entries.len() > CAP {
            let Some(oldest) = inner
                .entries
                .iter()
                .filter(|(_, e)| !e.in_flight && e.value.is_some())
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| *k)
            else {
                break;
            };
            evicted.extend(inner.entries.remove(&oldest));
        }

        evicted
    }
}

pub(crate) const CONFIGURE_TIMEOUT_MS: u64 = 5000;

pub async fn push_configure(
    hook: &crate::config::HookCfg,
    name: &str,
    settings_version: u64,
    env: &HookEnv,
) -> Result<(), String> {
    configure_resolved(
        gate_transport_offloaded(name, hook, env, settings_version).await,
        |transport, resolved| async move {
            transport
                .configure(
                    name,
                    &resolved,
                    settings_version,
                    applied_deadline(CONFIGURE_TIMEOUT_MS),
                )
                .await
                .map_err(|e| e.to_string())
        },
    )
    .await
}

pub(crate) async fn configure_resolved<T, F: std::future::Future<Output = Result<(), String>>>(
    loaded: Option<(T, ResolvedSettings)>,
    configure: impl FnOnce(T, ResolvedSettings) -> F,
) -> Result<(), String> {
    let Some((transport, resolved)) = loaded else {
        return Err("hook plugin unresolvable".to_string());
    };
    configure(transport, resolved).await
}

pub(crate) const TRANSPORT_RESOLVE_TIMEOUT_MS: u64 = CONFIGURE_TIMEOUT_MS;

pub(crate) fn applied_deadline(ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms)
}

pub(crate) async fn offload_bounded<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    offload_bounded_with_deadline(what, applied_deadline(TRANSPORT_RESOLVE_TIMEOUT_MS), f).await
}

pub(crate) async fn offload_bounded_with_deadline<T: Send + 'static>(
    what: &str,
    deadline: std::time::Duration,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    let task = tokio::task::spawn_blocking(f);
    match tokio::time::timeout(deadline, task).await {
        Ok(Ok(v)) => v,

        Ok(Err(e)) => {
            tracing::warn!(
                hook = %what, error = %e,
                "hook transport resolution panicked; the hook is treated as unresolvable"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                hook = %what, timeout_ms = deadline.as_millis() as u64,
                "hook transport resolution timed out; the hook is treated as unresolvable and the \
                 blocking thread is abandoned"
            );
            None
        }
    }
}

pub(crate) async fn gate_transport_offloaded(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    settings_version: u64,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    let (name_owned, hook, env) = (name.to_string(), hook.clone(), env.clone());
    offload_bounded(name, move || {
        gate_transport_named(&name_owned, &hook, &env, settings_version)
    })
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub fn transport_publication_for_test(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> Option<(bool, bool)> {
    let key = resolution::key(name, hook, env)?;
    Some((resolution::published(key), resolution::in_flight(key)))
}

pub async fn fetch_status(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<busbar_contract::hooks::HookStatus> {
    let (transport, _resolved) =
        gate_transport_offloaded(name, hook, env, settings_version).await?;
    transport
        .status(applied_deadline(CONFIGURE_TIMEOUT_MS))
        .await
}

/// The settings keys a hook reports differently from its definition. `sources`: the shorthand of
/// the generation that defines it (SECRET-SHORTHAND-BOOT §3.4).
pub fn settings_drift_keys(
    hook: &crate::config::HookCfg,
    reported: Option<&busbar_contract::plugin_settings::Settings>,
    sources: &busbar_contract::secret_ref::Sugars,
) -> Vec<String> {
    let Some(observed) = reported else {
        return Vec::new();
    };
    hook.settings.drift_keys(observed, sources)
}

pub async fn fetch_schema(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<busbar_contract::hooks::HookSchema> {
    let (transport, _resolved) =
        gate_transport_offloaded(name, hook, env, settings_version).await?;

    transport
        .describe(applied_deadline(CONFIGURE_TIMEOUT_MS))
        .await
}

pub(crate) fn resolve_on_error_chain<'a>(
    hook: &'a crate::config::HookCfg,
    hooks: &'a crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> (Vec<FallbackHook>, crate::config::PolicyOnError) {
    let mut chain: Vec<FallbackHook> = Vec::new();
    let mut visited: Vec<&str> = Vec::new();
    let mut current: &'a str = hook.on_error.as_str();
    loop {
        if let Some(terminal) = crate::config::on_error_terminal(current) {
            return (chain, terminal);
        }

        if let Some((policy, timeout)) = crate::preflight::builtin_ranking(current) {
            chain.push(FallbackHook {
                policy,
                timeout,
                send_prompt: false,
                send_user: false,
                on_empty: crate::config::PolicyOnError::Reject,
            });
            return (chain, crate::config::PolicyOnError::Weighted);
        }
        if visited.contains(&current) {
            return (chain, crate::config::PolicyOnError::default());
        }
        let Some(h) = hooks.get(current) else {
            return (chain, crate::config::PolicyOnError::default());
        };
        if h.kind != crate::config::HookKind::Gate {
            return (chain, crate::config::PolicyOnError::default());
        }
        if let Some((policy, _resolved)) = gate_transport_named(current, h, env, settings_version) {
            let (send_prompt, send_user) = projection_grants(current, h, env);
            chain.push(FallbackHook {
                policy,
                timeout: policy_timeout(h.timeout_ms),
                send_prompt,
                send_user,
                on_empty: gate_on_empty(h),
            });
        }
        visited.push(current);
        current = h.on_error.as_str();
    }
}

pub(crate) fn gate_on_empty(hook: &crate::config::HookCfg) -> crate::config::PolicyOnError {
    hook.on_empty
        .clone()
        .unwrap_or(crate::config::PolicyOnError::Reject)
}

pub fn resolve_rewrite_hooks(
    hooks: &crate::config::hooks::HookRegistry,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for (name, hook) in rewrite_definitions(hooks, global_hooks, |name, hook| {
        admits_rewrite(name, hook, env)
    }) {
        if let Some(ResolvedPolicy::Policy {
            policy,
            timeout,
            on_error,
            on_error_chain,
            ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((
                hook.priority,
                timeout,
                with_rewrite_on_error(policy, on_error, on_error_chain),
            ));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

pub fn resolve_tap_hooks(
    hooks: &crate::config::hooks::HookRegistry,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
    stage: crate::config::HookStage,
) -> Vec<TapEntry> {
    let mut ranked: Vec<(u16, TapEntry)> = Vec::new();
    for (name, hook) in tap_definitions(hooks, global_hooks, stage) {
        if let Some(ResolvedPolicy::Policy {
            policy,
            timeout,
            send_prompt,
            ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((
                hook.priority,
                (timeout, send_prompt, policy, hook.groups.clone()),
            ));
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    ranked.into_iter().map(|(_, entry)| entry).collect()
}

pub fn resolve_gate_hooks(
    hooks: &crate::config::hooks::HookRegistry,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(u16, ResolvedPolicy)> {
    let mut ranked: Vec<(u16, ResolvedPolicy)> = Vec::new();
    for (name, hook) in decision_definitions(hooks, global_hooks) {
        if let Some(rp) = resolve_gate_transport(name, hook, hooks, env, settings_version) {
            ranked.push((hook.priority, rp));
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

pub fn resolve_container_gates<'a, M>(
    containers: impl Iterator<Item = (&'a str, &'a [String])>,
    section: &[String],
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> M
where
    M: Default + Extend<(String, Vec<(u16, ResolvedPolicy)>)>,
{
    let mut out = M::default();
    for (name, own) in containers.chain(std::iter::once((SECTION_SCOPE, &[][..]))) {
        let attached = attach_list(section, own);
        if attached.is_empty() {
            continue;
        }
        let resolved = resolve_gate_hooks(hooks, &attached, env, settings_version);
        if !resolved.is_empty() {
            out.extend([(name.to_string(), resolved)]);
        }
    }
    out
}

pub fn resolve_container_rewrites<'a, M>(
    containers: impl Iterator<Item = (&'a str, &'a [String])>,
    section: &[String],
    hooks: &crate::config::hooks::HookRegistry,
    env: &HookEnv,
    settings_version: u64,
) -> M
where
    M: Default + Extend<(String, Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)>)>,
{
    let mut out = M::default();
    for (name, own) in containers.chain(std::iter::once((SECTION_SCOPE, &[][..]))) {
        let attached = attach_list(section, own);
        if attached.is_empty() {
            continue;
        }
        let resolved = resolve_rewrite_hooks(hooks, &attached, env, settings_version);
        if !resolved.is_empty() {
            out.extend([(name.to_string(), resolved)]);
        }
    }
    out
}

/// A pool's resolved strategy binding, owning its word and instance name (`hooks::strategy`): built
/// once per config load for each pool that names a strategy word, never per request.
pub(crate) fn strategy_binding(
    word: &str,
    implicit: bool,
) -> crate::hooks::strategy::StrategyBinding {
    crate::hooks::strategy::StrategyBinding {
        word: Box::from(word),
        instance: Box::from(word),
        implicit,
    }
}

/// A hook's `status` metrics, parsed (per admin status read or snapshot refresh) off the request
/// path as 1.5.5 does, with every cut reported against hook `name` (`hooks::text_cut`).
pub fn parse_hook_status_metrics(
    name: &str,
    raw: &[serde_json::Value],
) -> Vec<busbar_contract::hook_wire::reply::HookMetric> {
    let (metrics, cuts) = busbar_contract::hook_wire::reply::parse_status_metrics_counted(raw);
    crate::hooks::text_cut::report_cuts(name, &cuts, crate::hooks::text_cut::cap_of);
    metrics
}
