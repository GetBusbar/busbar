// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

fn policy_timeout(timeout_ms: u64) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        crate::limits::default_policy_timeout_ms()
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms)
}

pub mod gate;
pub mod taps;

#[allow(unused_imports)]
pub use busbar_contract::hooks::{
    CallerIdentity, Candidate, PolicyError, PolicyResult, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};

#[allow(unused_imports)]
pub use busbar_contract::signal::{Signal, SignalBag, SignalValue};

pub fn requested_signals(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> RequestedSignals {
    let mut mask = RequestedSignals::default();
    for hook in hooks.values() {
        for &s in &hook.signals {
            mask.insert(s);
        }
    }
    mask
}

pub fn any_content_hook(hooks: &std::collections::HashMap<String, crate::config::HookCfg>) -> bool {
    hooks.values().any(|h| h.prompt.sends_prompt())
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
    axis: Option<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>>,
    route_calls: Arc<std::collections::HashMap<String, RouteCalls>>,
    /// Declared paths read once outside cache admission. Reading a linked row's Statement may
    /// invoke its door, so the cache key must consult this snapshot instead of the registry.
    resolution_paths: Arc<resolution::Paths>,
    /// The secret resolver turns typed hook references, such as a `licenseKey`, into their raw values before settings cross the ABI at open/configure. It is the same fail-closed resolver shared with store and auth opens, held through the neutral [`busbar_contract::secret::SecretResolve`] trait rather than the concrete engine resolver. Wiring supplies the identical resolver instance; only the static type at the hook boundary is narrowed.
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
    banner_seen: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
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
            route_calls: Arc::new(std::collections::HashMap::new()),
            resolution_paths,
            secret_resolver,
            banner_seen: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
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
            route_calls: Arc::new(std::collections::HashMap::new()),
            resolution_paths,
            secret_resolver,
            banner_seen: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        }
    }

    fn knows(&self, module: &str) -> bool {
        self.registry.resolve(module).is_some()
            || self.axis.as_ref().is_some_and(|a| a.linked(module))
    }

    fn open(
        &self,
        module: &str,
        settings: &ResolvedSettings,
        name: &str,
        timeout_ms: u64,
    ) -> Result<Arc<dyn RoutingPolicy>, String> {
        if let Some(opened) = self.route_calls.get(name).filter(|opened| {
            opened.module == module
                && opened.resolved.as_value() == settings.as_value()
                && opened.budget == policy_timeout(timeout_ms)
        }) {
            return Ok(crate::plane_driver::hooks::policy::HookPolicy::policy(
                opened.calls.clone(),
                name,
            ));
        }
        let axis = self
            .axis
            .as_ref()
            .ok_or_else(|| format!("no `kind: hook` plugin answers to '{module}'"))?;
        let calls = axis.open(
            module,
            name,
            settings.as_value(),
            policy_timeout(timeout_ms),
        )?;
        Ok(crate::plane_driver::hooks::policy::HookPolicy::policy(
            calls, name,
        ))
    }

    pub fn route_decls(
        &mut self,
        hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    ) -> Result<Vec<crate::plugin_routes::RouteDecl>, String> {
        let Some(axis) = self.axis.as_ref() else {
            return Ok(Vec::new());
        };
        let mut names: Vec<_> = hooks.keys().collect();
        names.sort();
        let mut calls = std::collections::HashMap::new();
        let mut declarations = Vec::new();
        for name in names {
            let hook = &hooks[name];
            let resolved = self.resolve_hook_settings(&hook.plugin, &hook.settings)?;
            let routes = axis.routes(&hook.plugin, name, resolved.as_value())?;
            if routes.is_empty() {
                continue;
            }
            let budget = policy_timeout(hook.timeout_ms);
            let opened = match self.route_calls.get(name).filter(|opened| {
                opened.module == hook.plugin
                    && opened.resolved.as_value() == resolved.as_value()
                    && opened.budget == budget
                    && opened.calls.routes() == routes.as_slice()
            }) {
                Some(opened) => opened.calls.clone(),
                None => axis.open(&hook.plugin, name, resolved.as_value(), budget)?,
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
                    definition: ResolvedSettings::from_map(hook.settings.clone()),
                    resolved,
                    budget,
                    calls: opened,
                },
            );
        }
        self.route_calls = Arc::new(calls);
        Ok(declarations)
    }

    fn resolve_hook_settings(
        &self,
        module: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
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
        hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    ) -> Result<(), String> {
        for (name, hook) in hooks {
            self.resolve_hook_settings(&hook.plugin, &hook.settings)
                .map_err(|e| format!("hook '{name}' settings: {e}"))?;
        }
        Ok(())
    }

    pub fn preopen_gate_hooks(
        &self,
        hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    ) -> Result<(), String> {
        for (name, hook) in hooks {
            if hook.kind != crate::config::HookKind::Gate {
                continue;
            }

            if !self.knows(&hook.plugin) {
                continue;
            }

            let resolved = self
                .resolve_hook_settings(&hook.plugin, &hook.settings)
                .map_err(|e| format!("hook '{name}' settings: {e}"))?;
            self.open(&hook.plugin, &resolved, name, hook.timeout_ms)
                .map_err(|e| {
                    format!(
                        "gate hook '{name}' (plugin '{}') failed to open; refusing to boot/reload \
                         with a silently-absent admission gate (fail-closed): {e}",
                        hook.plugin
                    )
                })?;
        }
        Ok(())
    }
}

struct RouteCalls {
    module: String,
    definition: ResolvedSettings,
    resolved: ResolvedSettings,
    budget: std::time::Duration,
    calls: Arc<dyn busbar_contract::hook_calls::HookCalls>,
}

struct HookHttp {
    calls: Arc<dyn busbar_contract::hook_calls::HookCalls>,
    budget: std::time::Duration,
}

impl crate::plugin_routes::PluginHttpDispatch for HookHttp {
    fn handle_http(
        &self,
        request: &busbar_contract::abi::mechanism::endpoint::EndpointRequest,
    ) -> busbar_contract::abi::mechanism::endpoint::EndpointResponse {
        match tokio::runtime::Handle::current()
            .block_on(self.calls.serve(request.clone(), self.budget))
        {
            Ok(response) => response,
            Err(why) => {
                tracing::warn!(hook = self.calls.name(), error = %why, "hook route failed");
                busbar_contract::abi::mechanism::endpoint::EndpointResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            }
        }
    }
}

pub fn resolve_policy(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    let name = cfg.policy.native_name()?;

    let (policy, timeout) = crate::preflight::builtin_ranking(name)?;
    Some(ranked_policy(policy, timeout))
}

fn ranked_policy(policy: Arc<dyn RoutingPolicy>, timeout: std::time::Duration) -> ResolvedPolicy {
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

pub fn default_hook_name(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> Option<&str> {
    hooks
        .iter()
        .find(|(_, h)| h.default)
        .map(|(name, _)| name.as_str())
}

pub fn resolve_pool_ordering(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    default_hook: Option<&str>,
    settings_version: u64,
) -> Result<Option<ResolvedPolicy>, String> {
    if !cfg.base_named {
        if let Some(name) = default_hook {
            if let Some(hook) = hooks.get(name) {
                if hook.kind == crate::config::HookKind::Gate && !hook.prompt.can_rewrite() {
                    return Ok(resolve_gate_transport(
                        name,
                        hook,
                        hooks,
                        env,
                        settings_version,
                    ));
                }
                tracing::warn!(
                    hook = %name,
                    "`default: true` hook is not a decision gate; ignored as the base ordering \
                     (the compiled-in weighted backstop applies)"
                );
            }
        }
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

pub fn resolve_pool_gates(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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
            ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((
                hook.priority,
                timeout,
                with_rewrite_on_error(policy, on_error),
            ));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

fn failed_rewrite(
    on_error: &crate::config::PolicyOnError,
    message: String,
) -> busbar_contract::hooks::TransformOutcome {
    if failed_call_refuses(on_error) {
        busbar_contract::hooks::TransformOutcome::Reject {
            status: REQUIRED_HOOK_UNAVAILABLE_STATUS,
            message: REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string(),
        }
    } else {
        busbar_contract::hooks::TransformOutcome::Failed { message }
    }
}

struct RewriteOnError {
    inner: Arc<dyn RoutingPolicy>,
    on_error: crate::config::PolicyOnError,
}

#[async_trait::async_trait]
impl RoutingPolicy for RewriteOnError {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: std::time::Duration,
    ) -> PolicyResult {
        self.inner.decide(req, candidates, ctx, budget).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn name_arc(&self) -> std::sync::Arc<str> {
        self.inner.name_arc()
    }

    async fn transform(
        &self,
        req: &RoutingRequest<'_>,
        budget: std::time::Duration,
    ) -> busbar_contract::hooks::TransformOutcome {
        match self.inner.transform(req, budget).await {
            busbar_contract::hooks::TransformOutcome::Failed { message } => {
                if busbar_kernel::hooks::failed_call_refuses(&self.on_error) {
                    tracing::warn!(
                        hook = self.inner.name(),
                        error = %message,
                        "rewrite hook call failed and the hook is declared load-bearing \
                         (on_error: reject); refusing the request"
                    );
                }
                failed_rewrite(&self.on_error, message)
            }
            other => other,
        }
    }

    /// A rewrite the plane refuses to apply is this hook's failure: the same disposition, by the
    /// same rule, as a failed call.
    fn refuses_failed_rewrite(&self) -> bool {
        busbar_kernel::hooks::failed_call_refuses(&self.on_error)
    }

    async fn configure(
        &self,
        hook_name: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        settings_version: u64,
        budget: std::time::Duration,
    ) -> Result<(), PolicyError> {
        self.inner
            .configure(hook_name, settings, settings_version, budget)
            .await
    }

    async fn describe(&self, budget: std::time::Duration) -> Option<serde_json::Value> {
        self.inner.describe(budget).await
    }

    async fn status(
        &self,
        budget: std::time::Duration,
    ) -> Option<busbar_contract::hooks::HookStatus> {
        self.inner.status(budget).await
    }

    async fn notify(
        &self,
        tap: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        budget: std::time::Duration,
    ) {
        self.inner.notify(tap, budget).await;
    }
}

fn with_rewrite_on_error(
    policy: Arc<dyn RoutingPolicy>,
    on_error: crate::config::PolicyOnError,
) -> Arc<dyn RoutingPolicy> {
    Arc::new(RewriteOnError {
        inner: policy,
        on_error,
    })
}

fn resolve_gate_transport(
    name: &str,
    hook: &crate::config::HookCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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

fn hook_inert_gate_banner(
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
struct Needs {
    prompt: busbar_contract::plugin_rows::NeedLevel,
    user: busbar_contract::plugin_rows::NeedLevel,
}

impl Needs {
    fn declares_any(&self) -> bool {
        self.prompt.wants_read() || self.user.wants_read()
    }
}

fn effective_access(
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

fn access_from_intent(
    name: &str,
    hook: &crate::config::HookCfg,
    needs: Needs,
    banner_seen: &std::sync::Mutex<std::collections::HashSet<String>>,
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
            Some(banner)
                if banner_seen
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(name.to_string()) =>
            {
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

fn projection_grants(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> (bool, bool) {
    let (prompt, user) = effective_access(name, hook, env);
    (prompt.sends_prompt(), user.sends_user())
}

fn decision_definitions<'a>(
    hooks: &'a std::collections::HashMap<String, crate::config::HookCfg>,
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

fn tap_definitions<'a>(
    hooks: &'a std::collections::HashMap<String, crate::config::HookCfg>,
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

fn rewrite_definitions<'a>(
    hooks: &'a std::collections::HashMap<String, crate::config::HookCfg>,
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

fn admits_rewrite(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> bool {
    effective_access(name, hook, env).0.can_rewrite()
}

fn gate_transport_named(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    _settings_version: u64,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    if let Some(opened) = env.route_calls.get(name).filter(|opened| {
        opened.module == hook.plugin
            && *opened.definition == hook.settings
            && opened.budget == policy_timeout(hook.timeout_ms)
    }) {
        return Some((
            crate::plane_driver::hooks::policy::HookPolicy::policy(opened.calls.clone(), name),
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

fn gate_transport_uncached(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    let resolved = match env.resolve_hook_settings(&hook.plugin, &hook.settings) {
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
    match env.open(&hook.plugin, &resolved, name, hook.timeout_ms) {
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

type ResolvedSettings = crate::config::secret::ResolvedSettings;

type Resolved = (Arc<dyn RoutingPolicy>, ResolvedSettings);

mod resolution {
    use super::Resolved;
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex, OnceLock};

    const CAP: usize = 128;

    pub(super) struct Paths {
        registry: std::sync::Weak<dyn busbar_contract::plugin_rows::PluginRows>,
        modules: HashMap<String, Vec<String>>,
    }

    impl Paths {
        pub(super) fn new(
            registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        ) -> std::sync::Arc<Self> {
            let mut modules = HashMap::new();
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

    pub(super) fn key(
        name: &str,
        hook: &crate::config::HookCfg,
        env: &super::HookEnv,
    ) -> Option<u64> {
        use busbar_contract::secret_fields;
        use std::hash::{Hash as _, Hasher as _};

        if !std::sync::Weak::ptr_eq(
            &env.resolution_paths.registry,
            &std::sync::Arc::downgrade(&env.registry),
        ) {
            return None;
        }

        let paths = env.resolution_paths.modules.get(&hook.plugin)?;
        let settings = serde_json::Value::Object(hook.settings.clone());

        if secret_fields::undeclared_reference(&settings, &[]).is_some()
            || paths
                .iter()
                .any(|path| !secret_fields::declared_references(&settings, path).is_empty())
        {
            return None;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();

        (std::sync::Arc::as_ptr(&env.registry) as *const u8 as usize).hash(&mut h);
        name.hash(&mut h);
        hook.plugin.hash(&mut h);
        super::policy_timeout(hook.timeout_ms).hash(&mut h);
        settings.to_string().hash(&mut h);
        Some(h.finish())
    }

    pub(super) enum Admission {
        Published(Resolved),
        Claim(Claim),
    }

    pub(super) struct Claim {
        key: u64,
        published: bool,
    }

    impl Claim {
        pub(super) fn publish(mut self, value: Resolved) {
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

    pub(super) fn admit(
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
    pub(super) fn published(key: u64) -> bool {
        let (lock, _) = state();
        let inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.get(&key).is_some_and(|e| e.value.is_some())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn in_flight(key: u64) -> bool {
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

const CONFIGURE_TIMEOUT_MS: u64 = 5000;

pub async fn push_configure(
    hook: &crate::config::HookCfg,
    name: &str,
    settings_version: u64,
    env: &HookEnv,
) -> Result<(), String> {
    let Some((transport, resolved)) =
        gate_transport_offloaded(name, hook, env, settings_version).await
    else {
        return Err("hook plugin unresolvable".to_string());
    };
    transport
        .configure(
            name,
            &resolved,
            settings_version,
            applied_deadline(CONFIGURE_TIMEOUT_MS),
        )
        .await
        .map_err(|e| e.to_string())
}

const TRANSPORT_RESOLVE_TIMEOUT_MS: u64 = CONFIGURE_TIMEOUT_MS;

fn applied_deadline(ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms)
}

async fn offload_bounded<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    offload_bounded_with_deadline(what, applied_deadline(TRANSPORT_RESOLVE_TIMEOUT_MS), f).await
}

async fn offload_bounded_with_deadline<T: Send + 'static>(
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

async fn gate_transport_offloaded(
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

#[cfg(any(test, feature = "test-support"))]
pub async fn resolve_transport_for_test(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    settings_version: u64,
) -> bool {
    gate_transport_offloaded(name, hook, env, settings_version)
        .await
        .is_some()
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

pub fn settings_drift_keys(
    hook: &crate::config::HookCfg,
    reported: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Vec<String> {
    let Some(observed) = reported else {
        return Vec::new();
    };
    let mut keys: Vec<String> = hook
        .settings
        .iter()
        .filter(|(k, v)| match crate::config::secret::classify_setting(v) {
            crate::config::secret::SettingShape::Reference(_) => false,
            crate::config::secret::SettingShape::Verbatim(want) => observed.get(*k) != Some(want),
        })
        .map(|(k, _)| k.clone())
        .collect();
    keys.sort();
    keys
}

pub async fn fetch_schema(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<serde_json::Value> {
    let (transport, _resolved) =
        gate_transport_offloaded(name, hook, env, settings_version).await?;

    transport
        .describe(applied_deadline(CONFIGURE_TIMEOUT_MS))
        .await
}

fn resolve_on_error_chain<'a>(
    hook: &'a crate::config::HookCfg,
    hooks: &'a std::collections::HashMap<String, crate::config::HookCfg>,
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

fn gate_on_empty(hook: &crate::config::HookCfg) -> crate::config::PolicyOnError {
    hook.on_empty
        .clone()
        .unwrap_or(crate::config::PolicyOnError::Reject)
}

pub fn resolve_rewrite_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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
            ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((
                hook.priority,
                timeout,
                with_rewrite_on_error(policy, on_error),
            ));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

pub fn resolve_tap_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
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

#[allow(unused_imports)]
pub use busbar_kernel::config::plane_sections::attach_list;

pub const SECTION_SCOPE: &str = busbar_contract::section::RESERVED_SECTION_KEYS[0];

pub fn resolve_container_gates<'a>(
    containers: impl Iterator<Item = (&'a str, &'a [String])>,
    section: &[String],
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> std::collections::HashMap<String, Vec<(u16, ResolvedPolicy)>> {
    let mut out = std::collections::HashMap::new();
    for (name, own) in containers.chain(std::iter::once((SECTION_SCOPE, &[][..]))) {
        let attached = attach_list(section, own);
        if attached.is_empty() {
            continue;
        }
        let resolved = resolve_gate_hooks(hooks, &attached, env, settings_version);
        if !resolved.is_empty() {
            out.insert(name.to_string(), resolved);
        }
    }
    out
}

#[allow(clippy::type_complexity)]
pub fn resolve_container_rewrites<'a>(
    containers: impl Iterator<Item = (&'a str, &'a [String])>,
    section: &[String],
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> std::collections::HashMap<String, Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)>> {
    let mut out = std::collections::HashMap::new();
    for (name, own) in containers.chain(std::iter::once((SECTION_SCOPE, &[][..]))) {
        let attached = attach_list(section, own);
        if attached.is_empty() {
            continue;
        }
        let resolved = resolve_rewrite_hooks(hooks, &attached, env, settings_version);
        if !resolved.is_empty() {
            out.insert(name.to_string(), resolved);
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/failed_policy_tests.rs"]
mod failed_policy_tests;

pub type TapEntry = (
    std::time::Duration,
    bool,
    Arc<dyn RoutingPolicy>,
    Vec<String>,
);

/// The per-generation, config-derived UNION of every hook's declared [`Signal`] set — a dense
/// bitmask ("which catalog entries does ANYTHING configured on this generation want"), consulted
/// with a single `AND`+compare BEFORE any compute fn runs ([`RequestedSignals::wants`]), never
/// call-then-discard.
///
/// Relocated here off `busbar_kernel::hooks::RequestedSignals` (App-retype WEDGE 2d) so the engine's
/// `EngineHost::requested_signals` seam returns a NEUTRAL type; core re-exports it (identity) and its
/// config-time builder (`busbar_kernel::hooks::requested_signals`, which takes core's `HookCfg`) stays
/// in core and drives [`insert`](RequestedSignals::insert).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedSignals(u64);

impl RequestedSignals {
    #[inline]
    pub fn wants(self, s: Signal) -> bool {
        debug_assert!(
            s.bit() < 64,
            "Signal::bit() exceeded the u64 bitmask width; grow RequestedSignals to a bitset"
        );
        self.0 & (1u64 << s.bit()) != 0
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn insert(&mut self, s: Signal) {
        self.0 |= 1u64 << s.bit();
    }
}

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub enum ResolvedPolicy {
    /// A constructed policy object (a dlopen hook plugin / native non-weighted) plus its fallback config.
    /// The default SWRR / weighted path is represented as `None` by `resolve_policy` (it constructs no
    /// policy object), so there is no `Weighted` variant — a weighted pool simply has no resolved
    /// policy and takes the inline SWRR branch.
    Policy {
        policy: Arc<dyn RoutingPolicy>,
        /// The TERMINAL the on_error chain bottoms out on (weighted/reject/first) — applied when
        /// the policy fails and every chain link (below) also fails.
        on_error: crate::config::PolicyOnError,
        /// The resolved on_error FALLBACK CHAIN: hooks/strategies fired IN ORDER when the policy
        /// errors or times out; the first that answers decides. Empty (the common case — a
        /// terminal was named directly) costs nothing. Resolved once at config load; boot
        /// validation proves termination (cycles/unknowns/taps never reach here).
        on_error_chain: Vec<FallbackHook>,
        timeout: std::time::Duration,
        /// Derived from the hook's `prompt` grant (`ro`/`rw`) — build + send the prompt content
        /// projection (default false, i.e. `prompt: no`).
        send_prompt: bool,
        /// Derived from the hook's `user` grant (`ro`) — build + send the caller identity projection
        /// (default false, i.e. `user: no`).
        send_user: bool,
        /// Gate `on_empty` — behavior when a `restrict` reply leaves an EMPTY candidate intersection.
        /// Default `Reject` (fail-closed; the spec default for a compliance restrict); `Weighted`
        /// is the advisory escape (fall back to SWRR over the FULL pool). Inert for non-restricting
        /// policies (native/order-only), which never produce an empty intersection.
        on_empty: crate::config::PolicyOnError,
    },
}

pub const DEFAULT_HOOK_CONTENT_MAX_BYTES: usize = 0;

static HOOK_CONTENT_MAX_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_HOOK_CONTENT_MAX_BYTES);

pub fn set_hook_content_max_bytes(bytes: usize) {
    HOOK_CONTENT_MAX_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

pub fn hook_content_max_bytes() -> usize {
    HOOK_CONTENT_MAX_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

#[must_use]
pub fn content_capped(p: PromptProjection<'_>) -> PromptProjection<'_> {
    let cap = hook_content_max_bytes();
    if cap == 0 {
        return p;
    }
    let bytes = p.system.as_deref().map(str::len).unwrap_or(0)
        + p.messages
            .iter()
            .map(|(role, text)| role.len() + text.len())
            .sum::<usize>();
    if bytes <= cap {
        return p;
    }
    metrics::counter!(crate::snapshot::HOOK_CONTENT_TRUNCATED_TOTAL).increment(1);
    PromptProjection {
        system: None,
        messages: Vec::new(),
    }
}

#[inline]
#[must_use]
pub fn failed_call_refuses(on_error: &crate::config::PolicyOnError) -> bool {
    match on_error {
        crate::config::PolicyOnError::Reject => true,
        crate::config::PolicyOnError::Weighted | crate::config::PolicyOnError::First => false,
    }
}

pub const REQUIRED_HOOK_UNAVAILABLE_STATUS: u16 = 503;

pub const REQUIRED_HOOK_UNAVAILABLE_MESSAGE: &str =
    "A required gate could not complete. Please retry shortly.";

/// One link in a gate's resolved `on_error` fallback chain: the fallback hook's transport plus
/// the per-hook config the firing site needs (its own deadline, ITS grants — a fallback never
/// sees a projection its own grants don't allow — and its own `on_empty`).
#[derive(Clone)]
pub struct FallbackHook {
    pub policy: Arc<dyn RoutingPolicy>,
    pub timeout: std::time::Duration,
    pub send_prompt: bool,
    pub send_user: bool,
    pub on_empty: crate::config::PolicyOnError,
}
