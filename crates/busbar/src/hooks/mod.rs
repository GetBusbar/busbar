// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pluggable routing policies.
//!
//! A pool may declare a routing **policy** that, given a cheap projection of the request, returns an
//! ordered **preference** of members — not a single pick. The ordered list feeds the failover loop
//! Busbar already has (`proxy::pick_among`): if the policy's #1 is tripped / excluded / at
//! capacity, Busbar walks to #2 using the existing breaker machinery. One transport-agnostic trait
//! (`RoutingPolicy`); a `kind: hook` dlopen PLUGIN (loaded over the hybrid ABI as a `DlopenPolicy`)
//! is the general out-of-core implementation, and the built-in ranking hooks (the `hooks/ranking/`
//! workspace crate) are the compiled-in ones. (1.5.0 retired the out-of-process socket/webhook
//! transports — a hook is now a signed, trusted, in-process plugin.)
//!
//! ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool resolves to `ResolvedPolicy::None`
//! at config load and NEVER constructs any of the projection types or enters this module's async
//! path. The hot path stays today's inline SWRR.
//!
//! This surface is PRODUCTION-WIRED: `proxy::decide_policy_order` builds the `RoutingRequest` +
//! `Candidate` projections from the live store signals and invokes the resolved policy on every
//! non-default request; `proxy::pick_among` walks the ranked order through the existing failover
//! loop. `resolve_policy` (below) constructs the ranking-hook / dlopen-plugin transports once at
//! config load.

use std::sync::Arc;

/// Resolve a configured `timeout_ms` into a `Duration`, treating `0` as "use the default". A code-built
/// `PolicyCfg` (e.g. a native shorthand) can carry `timeout_ms == 0` because serde's field default only
/// fires on the deserialize path; a literal `0ms` deadline would make every policy decision instantly
/// time out. This belt-and-suspenders guard pairs with the desugar-site stamp in `config.rs`.
fn policy_timeout(timeout_ms: u64) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        crate::limits::default_policy_timeout_ms()
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms)
}

/// THE PROTOCOL-BLIND REQUEST GATE — the seam that fires a hook for a request the pipeline knows
/// only as an [`crate::ir::facts::IrFacts`]. The MCP and A2A firing sites call it; the model plane's
/// own phase-2 reconcile (which also has a candidate set to reconcile) stays in `proxy::engine`.
pub(crate) mod gate;
pub(crate) mod plugin;
pub(crate) mod scrape;
pub(crate) mod wire;

// The HOOK CONTRACT — the `RoutingPolicy` trait and the read-only projections it is invoked with
// (`RoutingRequest`, `Candidate`, `RoutingContext`, `RoutingDecision`, …) — lives in the
// `busbar-api` crate (the one crate both the engine and every plugin build against). Re-exported
// here so engine-internal paths are unchanged.
// `PolicyError`/`PolicyResult` are re-exported for the `#[cfg(test)]` hook-seam tests (which
// implement `RoutingPolicy` against the engine's types); allow the unused-in-non-test warning.
#[allow(unused_imports)]
pub(crate) use busbar_api::{
    CallerIdentity, Candidate, PolicyError, PolicyResult, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};
// The "decision observability" signal catalog — `Signal`/`SignalValue`/
// `SignalBag` are re-exported here for the same reason the hook contract types above are: engine-
// internal paths reference them as `crate::hooks::Signal` etc.
#[allow(unused_imports)]
pub(crate) use busbar_api::{Signal, SignalBag, SignalValue};

/// The per-generation, config-derived UNION of every hook's declared [`Signal`] set — a dense
/// bitmask ("which catalog entries does ANYTHING configured on this generation want"), consulted
/// with a single `AND`+compare BEFORE any compute fn runs (`RequestedSignals::wants`), never
/// call-then-discard. Mirrors the 846e4931 `usage_sink.is_some()` precedent generalized from one
/// boolean to one bit per catalog entry.
///
/// SCOPE (deliberate, documented simplification for this additive pass): the bitmask is built ONCE
/// per config generation as the union across EVERY configured hook, not per-pool. A pool with zero
/// signal-declaring hooks still consults the same (possibly non-zero) global mask, so it may
/// compute a signal only some OTHER pool's hook actually reads — strictly cheaper than a
/// per-consumer mask (no per-request allocation to narrow it) at the cost of that coarser sharing,
/// an accepted trade-off. A per-pool mask is a natural, purely-internal follow-up; the WIRE
/// contract here does not change either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RequestedSignals(u64);

impl RequestedSignals {
    /// A single `u64` AND + compare — the same order of magnitude as the pre-existing
    /// `app.tap_hooks_response.is_empty()` early-out this design generalizes.
    #[inline]
    pub(crate) fn wants(self, s: Signal) -> bool {
        debug_assert!(
            s.bit() < 64,
            "Signal::bit() exceeded the u64 bitmask width; grow RequestedSignals to a bitset"
        );
        self.0 & (1u64 << s.bit()) != 0
    }

    /// True iff NOTHING is declared anywhere — the zero-cost default generation.
    #[inline]
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn insert(&mut self, s: Signal) {
        self.0 |= 1u64 << s.bit();
    }
}

/// Build the config generation's [`RequestedSignals`] from the UNION of every registered hook's
/// `signals:` declaration (`HookCfg::signals`, see `config::HookCfg`'s own doc comment for the
/// declaration surface). Called ONCE per config apply (alongside `hook_registry: cfg.hooks.clone()`
/// in `main.rs`'s `App` construction, and again from `admin::v1::service::rebuild_hook_derived` on
/// every admin snapshot that rewrites that registry) — never per request. A config with no hook declaring any
/// `signals:` (the overwhelming default, and every config that predates the catalog) yields the
/// all-zero mask, so every `requested.wants(_)` check downstream is `false` for that generation.
pub(crate) fn requested_signals(
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

/// Does ANY registered hook hold a prompt-CONTENT grant (`prompt: ro` or `prompt: rw`)?
///
/// THE COMPUTE GATE for the request IR, and deliberately the SAME mechanism as
/// [`requested_signals`] directly above: one boolean resolved ONCE per config apply and read on the
/// request path as a single load, never recomputed. A deployment that grants no hook access to
/// prompt content — the overwhelming default — never builds the IR for the hook seam at all.
///
/// THE PROPERTY THIS KEYS ON IS THE DEPLOYMENT'S, NOT THE REQUEST'S. "Same protocol in and out" is
/// the tempting alternative and it is the wrong question: the same-protocol short-circuit compares
/// the ingress protocol against the RESOLVED EGRESS OF THE HOP, which is not known until a lane has
/// been chosen — and a content hook may reroute the request across protocols before that point. The
/// IR must therefore exist before egress is chosen, so the gate can only ask something answerable at
/// boot.
///
/// Read from the DEFINITION registry (`App::hook_registry`), so the answer is a SUPERSET of the
/// hooks that actually fire: a granted hook that no pool wires still reads `true`. The one-sided
/// direction is deliberate — over-reporting costs an unused IR build, under-reporting would hand a
/// content-granted hook a view the request was never parsed into.
pub(crate) fn any_content_hook(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> bool {
    hooks.values().any(|h| h.prompt.sends_prompt())
}

/// The plugin-resolution environment threaded through every hook-transport builder: the validated
/// plugin registry (the ONLY resolution surface — a hook's `plugin:` ref opens a `DlopenPolicy`
/// through it) and the shared [`HookProjectors`] every `DlopenPolicy` uses to project the request and
/// parse the reply through the engine's own fail-closed `wire` normalizers. Cheap to clone (both are
/// `Arc`-backed); replaces the old `&reqwest::Client` the retired webhook transport needed.
#[derive(Clone)]
pub(crate) struct HookEnv {
    pub(crate) registry: std::sync::Arc<busbar_plugin_loader::PluginRegistry>,
    pub(crate) projectors: std::sync::Arc<busbar_plugin_loader::hook::HookProjectors>,
    /// The secret resolver used to turn any SecretRef-typed hook setting (e.g. a `licenseKey`) into
    /// its raw value BEFORE the settings cross the ABI at open/configure (ADR-0010). Shared with the
    /// store/auth open paths; the same fail-closed resolver.
    pub(crate) secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
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
    /// Bundle a registry + the shared projectors + the secret resolver into the resolution
    /// environment.
    pub(crate) fn new(
        registry: std::sync::Arc<busbar_plugin_loader::PluginRegistry>,
        secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
    ) -> Self {
        HookEnv {
            registry,
            projectors: plugin::projectors(),
            secret_resolver,
            banner_seen: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        }
    }

    /// Resolve a hook's opaque `settings:` map — substituting any SecretRef-typed value (e.g. a
    /// `licenseKey`) with its resolved secret — before the JSON crosses the ABI at open/configure.
    /// FAIL-CLOSED: an unresolvable ref is an `Err`, never a dangling reference handed to the plugin.
    fn resolve_hook_settings(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        crate::config::secret::resolve_settings(settings, &self.secret_resolver)
    }

    /// PRE-BUILD FAIL-CLOSED PASS: resolve every configured hook's SecretRef settings ONCE, up
    /// front, so that an unresolvable secret aborts boot/reload the SAME way the store path
    /// (`build_app_from_config`) and the auth chain (`AuthMiddleware::new`) do. Without this pass a
    /// gate whose SecretRef fails to resolve would be silently `filter_map`-dropped from the routing
    /// chain by `resolve_pool_gates`/`resolve_on_error_chain` (fail-OPEN), so traffic the gate was
    /// configured to restrict/reject would flow unfiltered. This is the CRITICAL DISTINCTION: a
    /// *genuinely absent / unloadable* plugin still degrades to "gate absent" (the legitimate
    /// safety-net `None`, already gated loud by `plugins_preflight`), but a *secret that failed to
    /// resolve* must fail the boot/reload CLOSED — never quietly disable the gate.
    ///
    /// Returns `Err` naming the offending hook on the first unresolvable secret. Called once from
    /// `build_app_from_config` before any `resolve_*` consumes the hooks.
    pub(crate) fn preresolve_hook_secrets(
        &self,
        hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    ) -> Result<(), String> {
        for (name, hook) in hooks {
            self.resolve_hook_settings(&hook.settings)
                .map_err(|e| format!("hook '{name}' settings: {e}"))?;
        }
        Ok(())
    }

    /// PRE-BUILD FAIL-CLOSED PASS for gate/rewrite OPEN() failures (the open-time variant):
    /// actually `open()` every referenced DECISION or REWRITE gate up front so an `open()`-time
    /// failure (the plugin constructor rejecting its cfg_json, a staging/mmap failure, an
    /// ABI/transport-version or exported-kind mismatch observable only on load) ABORTS boot/reload —
    /// the SAME fail-closed discipline the store (`open_store`) and auth (`AuthMiddleware::new`)
    /// paths use. Without this pass, `resolve_pool_gates`/`resolve_pool_rewrites`/
    /// `resolve_rewrite_hooks`/`resolve_gate_hooks` all `filter_map`/`if let Some`-DROP a gate whose
    /// plugin failed to `open()`, so a Reject/restrict/rewrite gate the operator configured would
    /// silently vanish while boot/reload reports success — a fail-OPEN of an admission control.
    /// `plugins_preflight` is manifest-only (no dlopen) and `preresolve_hook_secrets` only resolves
    /// SecretRefs, so neither catches an `open()` failure.
    ///
    /// CRITICAL DISTINCTION (matching `preresolve_hook_secrets`): a plugin that is GENUINELY ABSENT
    /// (`registry.resolve` = `None`) is the legitimate safety-net skip and stays fail-open (already
    /// surfaced loudly by `plugins_preflight` for a *referenced* plugin) — we do NOT abort for it
    /// here. But a plugin that IS present and resolvable yet fails `open()` MUST abort. Taps
    /// (observation-only) legitimately fail-open and are excluded — only decision and rewrite gates,
    /// whose absence changes an admission/redaction decision, are pre-opened.
    ///
    /// Opening here is consistent with the transport model (every `gate_transport_named` opens a
    /// fresh instance; `fetch_status`/`push_configure` open per call), so this pre-open does not
    /// leak a live instance — the constructed policy is dropped at the end of the iteration.
    pub(crate) fn preopen_gate_hooks(
        &self,
        hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    ) -> Result<(), String> {
        for (name, hook) in hooks {
            // Only decision + rewrite GATES fail closed. Taps observe (fail-open by design); a
            // non-gate kind never enforces an admission/redaction decision.
            if hook.kind != crate::config::HookKind::Gate {
                continue;
            }
            // Genuinely-absent plugin: the legitimate safety-net skip (fail-open). We only pre-open
            // a plugin that actually resolves — `plugins_preflight` already loudly flags a
            // referenced-but-unloadable plugin, and a truly missing plugin degrades to "gate absent"
            // exactly as before. This is the DISTINCTION between absent (ok) and open()-failed (abort).
            if self.registry.resolve(&hook.plugin).is_none() {
                continue;
            }
            // The plugin IS present: resolve its (already-secret-substituted) settings and OPEN it.
            // An open failure here is a hard boot/reload error — the gate would otherwise be silently
            // dropped and its admission/rewrite decision lost.
            let resolved = self
                .resolve_hook_settings(&hook.settings)
                .map_err(|e| format!("hook '{name}' settings: {e}"))?;
            let cfg_json = serde_json::Value::Object(resolved).to_string();
            self.registry
                .open_hook(&hook.plugin, &cfg_json, name, self.projectors.clone())
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

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub(crate) enum ResolvedPolicy {
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

/// One link in a gate's resolved `on_error` fallback chain: the fallback hook's transport plus
/// the per-hook config the firing site needs (its own deadline, ITS grants — a fallback never
/// sees a projection its own grants don't allow — and its own `on_empty`).
#[derive(Clone)]
pub(crate) struct FallbackHook {
    pub(crate) policy: Arc<dyn RoutingPolicy>,
    pub(crate) timeout: std::time::Duration,
    pub(crate) send_prompt: bool,
    pub(crate) send_user: bool,
    pub(crate) on_empty: crate::config::PolicyOnError,
}

/// Resolve a pool's routing config into a runtime policy ONCE at config load. Returns `None` for the
/// ZERO-COST default path: `route: weighted` (the default / absent case) AND the explicit
/// `route: native, policy.name: weighted` form both resolve to `None`, because `weighted` Abstains
/// and thus converges with today's inline SWRR — so the hot path constructs no policy object, builds
/// no projections, and takes the unchanged `select_weighted_in` branch.
///
/// This resolves the BASE only. A pool's GATES are resolved separately (`resolve_pool_gates`) and
/// fire in the phase-2 decision reconcile — a gate's `order` overrides the base; its abstain falls
/// through to the base. The resolved base is stored on `PoolRuntime::policy` and consumed
/// per-request by `proxy::decide_policy_order`.
pub(crate) fn resolve_policy(cfg: &crate::config::PoolCfg) -> Option<ResolvedPolicy> {
    // `weighted` ⇒ the zero-cost default path (no policy object, inline SWRR) — byte-identical to
    // 1.2.1's `route: weighted` — so `native_name()` returns `None` here and we take the `?`
    // short-circuit BELOW regardless of the ranking feature.
    let name = cfg.policy.native_name()?;
    // The non-weighted ranking strategies are the `hooks-ranking` plugin. When it's compiled OUT, a
    // `policy: cheapest` (etc.) is a config_validate BOOT ERROR, so this arm is unreachable in a
    // running server; degrade to None (SWRR) as belt-and-suspenders.
    #[cfg(feature = "hooks-ranking")]
    {
        let policy = busbar_hooks_ranking::native_policy(name)?;
        Some(ResolvedPolicy::Policy {
            policy,
            on_error: crate::config::PolicyOnError::default(),
            on_error_chain: Vec::new(),
            timeout: policy_timeout(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
            // Native policies rank on live signals and have no reader for prompt/identity.
            send_prompt: false,
            send_user: false,
            // A native ordering policy never restricts, so on_empty is inert; keep the fail-closed default.
            on_empty: crate::config::PolicyOnError::Reject,
        })
    }
    #[cfg(not(feature = "hooks-ranking"))]
    {
        let _ = name;
        None
    }
}

/// The name of the registered `default: true` hook, if any — the base ordering that pools which named
/// none inherit. At most one exists (config_validate enforces it), so `find` is unambiguous.
pub(crate) fn default_hook_name(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> Option<&str> {
    hooks
        .iter()
        .find(|(_, h)| h.default)
        .map(|(name, _)| name.as_str())
}

/// Resolve a pool's base ordering, honoring the `default:` hook. A pool that named NO base ordering
/// (`base_named == false`) INHERITS the `default:` hook as its base (the default gate orders it) —
/// the REPLACEMENT of the compiled-in `weighted` backstop, per the everything-is-a-hook model. A pool
/// that explicitly named a base keeps its choice (the default does NOT override it); a pool's own
/// GATES are orthogonal — they fire in the phase-2 reconcile ON TOP of whatever base resolves here.
/// When no `default:` hook is registered, this is exactly `resolve_policy` (the compiled-in
/// backstop). Called once per pool at startup.
pub(crate) fn resolve_pool_ordering(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    default_hook: Option<&str>,
    settings_version: u64,
) -> Option<ResolvedPolicy> {
    if !cfg.base_named {
        if let Some(name) = default_hook {
            if let Some(hook) = hooks.get(name) {
                // Same exclusion both sibling resolvers apply (`resolve_pool_gates`,
                // `resolve_gate_hooks`): only a non-rewriting `kind: gate` can return an `order`.
                // A rw/tap/auth hook here would fire per request for a decision it structurally
                // cannot produce, paying its deadline for nothing. Keyed on the OPERATOR grant
                // (`can_rewrite`), not `admits_rewrite`, to match the siblings exactly.
                if hook.kind == crate::config::HookKind::Gate && !hook.prompt.can_rewrite() {
                    // The default gate becomes this pool's base ordering.
                    return resolve_gate_transport(name, hook, hooks, env, settings_version);
                }
                tracing::warn!(
                    hook = %name,
                    "`default: true` hook is not a decision gate; ignored as the base ordering \
                     (the compiled-in weighted backstop applies)"
                );
            }
        }
    }
    resolve_policy(cfg)
}

/// Resolve a pool's GATES (`hook:` / the non-strategy names in `hooks: [...]`) into their transports,
/// preserving CONFIG ORDER and carrying each hook's `priority` — the firing site merges these with
/// the global decision gates into one priority-sorted phase-2 chain (stable: ties keep globals-first,
/// then config order). Wrong-kind / genuinely-absent-plugin refs are skipped here — a skip degrades
/// to "gate absent", never a stranded request. An `open()`-time FAILURE of a present plugin does NOT
/// silently vanish: `HookEnv::preopen_gate_hooks` (a fail-closed pre-build pass in
/// `build_app_from_config`) opens every referenced gate and ABORTS boot/reload on failure, so by the
/// time this runs a present gate either opens or the boot already failed.
pub(crate) fn resolve_pool_gates(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(u16, ResolvedPolicy)> {
    let mut ranked: Vec<(u16, ResolvedPolicy)> = cfg
        .gates
        .iter()
        .filter_map(|name| {
            let hook = hooks.get(name)?;
            if hook.kind != crate::config::HookKind::Gate {
                return None;
            }
            // A `prompt: rw` gate is a phase-1 REWRITE (resolved by `resolve_pool_rewrites`), not
            // a phase-2 decision gate — including it here would fire it for a decision it never
            // returns (its rewrite reply normalizes to Abstain), paying its deadline for nothing.
            // Keyed on the OPERATOR grant, not `admits_rewrite`: a manifest-denied `rw` hook goes
            // inert with a warn rather than being promoted into a decision gate it never asked for.
            if hook.prompt.can_rewrite() {
                return None;
            }
            resolve_gate_transport(name, hook, hooks, env, settings_version)
                .map(|rp| (hook.priority, rp))
        })
        .collect();
    // Sorted HERE, at config-resolve time, exactly as `resolve_gate_hooks` sorts the globals —
    // STABLE, so config order still breaks priority ties. The phase-2 seam then merges two
    // already-sorted runs per request instead of re-collecting and re-sorting the whole chain on
    // every request that reaches it. Same resulting order, no hot-path allocation.
    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

/// Resolve a pool's REWRITE gates — the `prompt: rw` gates in its `hooks: [...]` list — into the
/// pool's phase-1 transform chain, sorted by ascending `priority` (stable: config order breaks
/// ties). Fired AFTER the global rewrite chain for requests routed to this pool (each chain is
/// internally priority-ordered; globals always precede pool rewrites). The EFFECTIVE rw access —
/// operator grant MEET signed-manifest `needs.prompt` ([`admits_rewrite`]) — is the admission
/// ticket, enforced here at resolution exactly as in `resolve_rewrite_hooks`.
pub(crate) fn resolve_pool_rewrites(
    cfg: &crate::config::PoolCfg,
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for name in &cfg.gates {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        // EFFECTIVE rw, not the operator grant alone: `admits_rewrite` is the same
        // belt-and-suspenders meet the read projections go through.
        if hook.kind != crate::config::HookKind::Gate || !admits_rewrite(name, hook, env) {
            continue;
        }
        if let Some(ResolvedPolicy::Policy {
            policy, timeout, ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((hook.priority, timeout, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

/// Resolve a GATE hook into a [`ResolvedPolicy`]. The prompt/identity projections are gated by BOTH
/// the operator's `prompt:`/`user:` grant AND the plugin's signed-manifest declared intent (`needs:`)
/// — the belt-and-suspenders projection rule: the core sends content ONLY when both agree
/// ([`projection_grants`]). A GENUINELY-ABSENT plugin degrades to `None` (fail-open safety net); an
/// `open()`-time FAILURE of a present plugin is caught earlier by `HookEnv::preopen_gate_hooks`,
/// which aborts boot/reload — so a present gate never reaches here having silently failed to open.
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

/// Return the loud INERT-GATE banner for a hook whose operator `prompt: rw` grant exceeds what its
/// signed manifest declares (the caller has already confirmed `grant.can_rewrite() &&
/// !needs_prompt.wants_rewrite()`), or `None` when the hook can't actually fall out of both admission
/// chains this way. Only a `kind: gate` hook can: `resolve_pool_gates`/`resolve_gate_hooks` exclude a
/// `prompt: rw` hook from the phase-2 DECISION chain unconditionally on the raw operator grant
/// (deliberate — a manifest-denied `rw` hook is never promoted into a decision gate it never asked
/// for), and `resolve_pool_rewrites`/`resolve_rewrite_hooks` exclude it from the phase-1 REWRITE chain
/// on the effective grant (this same mismatch). Together that's every chain a gate can join. A
/// `kind: tap` hook was never in either chain to begin with (a tap can't decide or rewrite), so the
/// same mismatch on a tap is just a fat-fingered grant, not a silent outage — it keeps the plain warn.
///
/// Mirrors `open_relay_banner`/`inert_durable_keys_banner` in `main.rs`: same wording register (names
/// the offender, states the mechanism, states the fix), same severity discipline (the caller logs
/// this at `error!` AND unconditionally on stderr — never only `warn!`, which is suppressed under
/// `RUST_LOG=error`, the very level a production operator is most likely to run).
///
/// Deliberately does NOT claim the hook "never fires under any circumstance": `resolve_on_error_chain`
/// pushes ANY `kind: gate` hook named as another hook's `on_error` target (no `can_rewrite` filter
/// there), so a hook in this exact state can still be reached as a fallback link, contributing its
/// decision verdict there (never its rewrite arm — that still normalizes to abstain). The banner
/// therefore names the two chains it is excluded from precisely, rather than asserting total silence.
fn hook_inert_gate_banner(
    name: &str,
    plugin: &str,
    kind: crate::config::HookKind,
    needs_prompt: busbar_plugin_sign::NeedLevel,
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

/// THE choke point for the belt-and-suspenders rule: effective access is the operator's grant MEET
/// the plugin's signed-manifest `needs:`, on the ladder `no ⊂ ro ⊂ rw`. Read, rewrite and identity
/// admission must all derive from here — a consumer that re-derives from `hook.prompt` bypasses the
/// manifest gate.
///
/// An unresolvable manifest falls back to the operator grant alone; pre-flight already fails boot
/// on an unresolvable ref, so that branch is a safety net, never the live path.
fn effective_access(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> (crate::config::PromptAccess, crate::config::UserAccess) {
    use crate::config::{PromptAccess, UserAccess};
    use busbar_plugin_sign::NeedLevel;

    let grant_prompt = hook.prompt;
    let grant_user = hook.user;
    let Some(p) = env.registry.resolve(&hook.plugin) else {
        return (grant_prompt, grant_user);
    };
    let needs = &p.manifest.needs;
    // MEET on the ladder: the effective rung is the lower of the two declarations.
    let eff_prompt = match (grant_prompt, needs.prompt) {
        (PromptAccess::No, _) | (_, NeedLevel::No) => PromptAccess::No,
        (PromptAccess::Rw, NeedLevel::Rw) => PromptAccess::Rw,
        _ => PromptAccess::Ro,
    };
    let eff_user = match (grant_user, needs.user) {
        (UserAccess::No, _) | (_, NeedLevel::No) => UserAccess::No,
        _ => UserAccess::Ro,
    };
    // Surface a fat-fingered grant that the manifest never declared: the projection is a no-op, but
    // the operator should know the grant is inert (they may have the wrong plugin).
    if grant_prompt.sends_prompt() && !needs.prompt.wants_read() {
        tracing::warn!(
            hook = %name, plugin = %hook.plugin,
            "hook grants `prompt` but the plugin manifest declares no prompt need — no prompt \
             content will be sent (grant is inert)"
        );
    }
    // The WRITE half: a manifest declaring at most `ro` must not be admitted to a rewrite chain —
    // it attested it does not rewrite. See `hook_inert_gate_banner` for why a `kind: gate` hook here
    // is not merely "no rewrite chain" but silently inert on EVERY chain, and why the severity jumps
    // to a loud banner for a gate but stays a plain warn for a tap.
    if grant_prompt.can_rewrite() && !needs.prompt.wants_rewrite() {
        match hook_inert_gate_banner(name, &hook.plugin, hook.kind, needs.prompt) {
            // ONE print per hook per build (see `banner_seen`'s doc): a hook named in several pools'
            // `hooks:` lists resolves — and would otherwise re-banner — once per reference.
            Some(banner) if env.banner_seen.lock().unwrap().insert(name.to_string()) => {
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
    // Surface the declared intent at resolution (register/load visibility).
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

/// The READ half of [`effective_access`], as the `(send_prompt, send_user)` pair the wire
/// projections take.
fn projection_grants(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> (bool, bool) {
    let (prompt, user) = effective_access(name, hook, env);
    (prompt.sends_prompt(), user.sends_user())
}

/// The WRITE half of [`effective_access`]: may this hook join a REWRITE chain? Both rewrite
/// resolvers ask THIS, never `hook.prompt.can_rewrite()` — the operator grant alone is not enough.
fn admits_rewrite(name: &str, hook: &crate::config::HookCfg, env: &HookEnv) -> bool {
    effective_access(name, hook, env).0.can_rewrite()
}

/// Open the `kind: hook` PLUGIN backing this hook as a [`busbar_plugin_loader::DlopenPolicy`] — the
/// in-process replacement for the retired socket/webhook transports. The plugin's opaque `settings:`
/// map is its `open` config (verbatim JSON). `name` + `settings_version` are carried for diagnostics
/// and the configure ack. `None` when the reference doesn't resolve to a loadable `kind: hook`
/// plugin (the plugin pre-flight already fails boot on that, so a `None` here is a safety net that
/// degrades to "gate absent", never a stranded request). A SecretRef in `settings` that fails to
/// resolve is a DIFFERENT case: it is caught up front by `HookEnv::preresolve_hook_secrets` (which
/// aborts boot/reload CLOSED), so it never reaches this `None`-on-error path in practice.
///
/// Returns the transport TOGETHER WITH the resolved settings map it was opened against. The pairing
/// is the point: `push_configure` needs that same resolved bag to send in its `configure` call, and
/// when it resolved its own copy it did so INLINE on an `async fn`, one line above this function's
/// offloaded call — blocking FFI into a `kind: secret` plugin on a Tokio worker, and untimed
/// (`CONFIGURE_TIMEOUT_MS` bounds only the `configure` that follows). Handing the bag back from the
/// one place that already computes it means there is no second resolution for a caller to place on
/// the reactor.
fn gate_transport_named(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
    _settings_version: u64,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    // ONE load per distinct resolution, and that load is SINGLE-FLIGHT. See [`resolution`] for why
    // this is a correctness fix and not a cache for speed's sake. A hook carrying a `SecretRef` is
    // deliberately NOT eligible (`key` returns `None`) and re-resolves on every call, exactly as
    // before, because its resolved value can change under us without any of the key's inputs moving.
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

/// [`gate_transport_named`] with the resolution cache taken out of the picture — the actual secret
/// resolution + `dlopen` + plugin `open`. Split out so the cache is a single wrapper rather than a
/// pair of early returns threaded through the body.
fn gate_transport_uncached(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> Option<(Arc<dyn RoutingPolicy>, ResolvedSettings)> {
    // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret store BEFORE the
    // settings cross the ABI (ADR-0010). The FAIL-CLOSED guarantee lives in
    // `HookEnv::preresolve_hook_secrets`, called once from `build_app_from_config` BEFORE any gate is
    // resolved: an unresolvable hook secret aborts boot/reload there (matching the store/auth paths),
    // so this path is never reached with a dangling secret. This site therefore cannot silently drop
    // a gate whose secret failed to resolve — by the time we get here the secret has ALREADY resolved.
    // A residual `Err` here (e.g. a race where the secret was rotated away after the pre-resolve pass)
    // is still treated conservatively as absent, but the pre-resolve pass is the real gate.
    let resolved = match env.resolve_hook_settings(&hook.settings) {
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
    let cfg_json = serde_json::Value::Object(resolved.clone()).to_string();
    match env
        .registry
        .open_hook(&hook.plugin, &cfg_json, name, env.projectors.clone())
    {
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

/// A hook's `settings:` map with every `SecretRef` already substituted for its resolved value —
/// i.e. the bag that crosses the ABI. Produced ONLY by [`gate_transport_named`] (and its offloaded
/// wrapper), so a caller cannot obtain one without having gone through the offload.
type ResolvedSettings = serde_json::Map<String, serde_json::Value>;

/// A resolved hook transport together with the settings bag it was opened against.
type Resolved = (Arc<dyn RoutingPolicy>, ResolvedSettings);

/// SINGLE-FLIGHT ADMISSION AND PUBLICATION FOR HOOK TRANSPORT RESOLUTION.
///
/// **This is not a cache for speed. It closes a real defect, and the defect is measurable.**
///
/// Resolving a hook transport stages the plugin's verified bytes and `dlopen`s them as a BRAND NEW
/// image. `dlopen` is serialised process-globally — the dynamic linker's own lock, plus per-inode
/// code-signature validation on macOS — so the cost of one load is O(number of loads in flight),
/// not O(size of the library). And this engine calls it on EVERY control-plane touch: per
/// `push_configure`, per `fetch_status` (i.e. per `/metrics/hooks` scrape refresh, which a
/// monitoring system performs on a fixed interval forever), per `fetch_schema`, per
/// `resolve_on_error_chain`, per reload. `busbar_plugin_loader`'s own `intern_name` doc already
/// names that list as the reason a per-open allocation had to be interned; the load itself was left
/// alone.
///
/// Measured on this tree, on the 2.1 MB `busbar-hook-test-plugin` cdylib (macOS, 18 cores), timing
/// the `Library::new` call alone:
///
/// | how it was run | p50 | p90 | max |
/// |---|---|---|---|
/// | one at a time | 250 ms | — | 3.8 s (first in the process) |
/// | 30 of them, otherwise idle machine | 1.9 s | — | 4.5 s |
/// | 137 of them, full `cargo test` workspace run | **5.9 s** | **30 s** | **88 s** |
///
/// The control plane's 5 s deadline is not a bound on the plugin's behaviour under those numbers —
/// it is a bet against a globally serialised queue that the engine itself is filling. Raising it
/// does not help: 88 s is past 60 s too, which is why the previous `cfg(test)` 60 s fork made the
/// symptom rarer and never removed it. The fix is to stop filling the queue.
///
/// **What is admitted.** A resolution is keyed by everything that decides what it IS: the plugin
/// registry it comes out of (by identity — a `plugins refresh` or a config reload builds a new one),
/// the plugin name, the hook name (it is the plugin's metrics id and crosses `open`) and the
/// verbatim settings bag. Same key ⇒ same `dlopen` of the same verified bytes with the same
/// `cfg_json` ⇒ the same transport, so reuse is not an approximation of the fresh load, it is the
/// fresh load.
///
/// **What is NOT admitted, and this is the part that must not be softened.** A hook whose settings
/// carry a `SecretRef` gets `None` from [`key`] and is resolved from scratch every single time. Its
/// resolved value can change (rotation) without any input to the key moving, so a reused transport
/// would be running last hour's credential while `settings_drift_keys` reported no drift. Freshness
/// there is the whole point of the secret indirection and it is not traded for a load.
///
/// **Single flight.** The claim is held ACROSS the load, so a second resolution of the same key
/// waits for the first instead of queueing its own `dlopen` behind it. That is what makes an
/// abandoned resolution harmless: `spawn_blocking` cannot be cancelled, so when
/// [`offload_bounded`]'s deadline elapses the load runs to completion anyway — and now it publishes,
/// so the caller that retries adopts it rather than starting the whole thing again.
///
/// **Bounded.** At most [`CAP`] published entries, oldest first, and an in-flight claim is never
/// evicted. Each entry holds one mapped plugin image, which is the same resource a configured hook
/// holds anyway — plus a `Weak` to the registry it came out of, which is what makes "which
/// registry" an identity rather than an address that can be reissued (see [`Entry::registry`]).
/// Entries whose registry is gone are dropped on the next eviction pass, ahead of the cap.
mod resolution {
    use super::Resolved;
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex, OnceLock};

    /// Published entries kept at once. Sized for "every hook a deployment configures, across a
    /// couple of settings generations", not for a working set — the eviction is a leak stop, not a
    /// hit-rate tuning knob.
    const CAP: usize = 128;

    struct Entry {
        /// Insertion order, for the oldest-first eviction.
        seq: u64,
        /// A resolution is in progress for this key: waiters block instead of starting their own.
        in_flight: bool,
        value: Option<Resolved>,
        /// THE REGISTRY THIS ENTRY IS KEYED ON, HELD WEAKLY — and the weak handle is what makes the
        /// key's registry half an identity rather than a coincidence. See [`key`].
        ///
        /// A `Weak` keeps the `Arc`'s ALLOCATION alive (the strong count reaching zero drops the
        /// registry's contents — every plugin image it owned is released on schedule — but the
        /// allocation itself is only returned once the weak count goes too). So for as long as an
        /// entry keyed on a registry exists, that registry's address CANNOT be handed back out by
        /// the allocator, and no future registry can collide with this key.
        ///
        /// Without it the cache had a live ABA defect: a published entry outlives the registry it
        /// was resolved against, the freed allocation is claimed by the very next
        /// `Arc<PluginRegistry>` (measured: the immediately following one, every time), and a
        /// resolution against a registry that never carried the plugin was served the DEAD
        /// registry's transport. That is not a stale cache entry, it is a gate resolving out of a
        /// plugin set the operator has already replaced — the exact thing a `plugins refresh` or a
        /// config reload does to the old registry. Pinned by
        /// `a_reused_registry_address_never_inherits_a_dead_registrys_resolution`.
        registry: std::sync::Weak<busbar_plugin_loader::PluginRegistry>,
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

    /// The identity of a resolution, or `None` when this hook is not eligible for reuse (any
    /// `SecretRef` in its settings — see the module doc).
    pub(super) fn key(
        name: &str,
        hook: &crate::config::HookCfg,
        env: &super::HookEnv,
    ) -> Option<u64> {
        use std::hash::{Hash as _, Hasher as _};
        if hook.settings.values().any(|v| {
            matches!(
                crate::config::secret::classify_setting(v),
                crate::config::secret::SettingShape::Reference(_)
            )
        }) {
            return None;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        // Registry IDENTITY, not contents: a `plugins refresh` or a config reload installs a NEW
        // `Arc<PluginRegistry>`, so every entry keyed on the old one is unreachable from that moment
        // and its plugin bytes can never be served again.
        //
        // The address is only an IDENTITY because every entry keyed on it holds a `Weak` to it
        // (see `Entry::registry`), which pins the allocation and so keeps the allocator from
        // reissuing that address to a different registry. This comment used to claim the resolving
        // closure's own `Arc` clone was enough; it is not — the closure's clone is gone the moment
        // the resolution returns, while the entry it published lives on.
        (std::sync::Arc::as_ptr(&env.registry) as *const u8 as usize).hash(&mut h);
        name.hash(&mut h);
        hook.plugin.hash(&mut h);
        serde_json::Value::Object(hook.settings.clone())
            .to_string()
            .hash(&mut h);
        Some(h.finish())
    }

    /// What a would-be resolver is told: someone already published this exact resolution, or you
    /// now hold the claim and must do the load.
    pub(super) enum Admission {
        Published(Resolved),
        Claim(Claim),
    }

    /// The right (and the duty) to perform ONE resolution for a key. `Drop` releases it and wakes
    /// every waiter, including on panic — a plugin constructor that blows up cannot wedge a key out
    /// of ever resolving again.
    pub(super) struct Claim {
        key: u64,
        published: bool,
    }

    impl Claim {
        /// Publish the resolution this claim was taken out for. Callers that resolved to `None`
        /// simply drop the claim instead: a failed load is not published, so the next caller retries
        /// it rather than inheriting a permanent "absent".
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
            // `self` drops here, releasing the claim (and running the eviction pass).
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
            // `_evicted` drops HERE, with the lock released — see `evict_over_cap`.
        }
    }

    /// Take the claim for `key`, or hand back what a previous resolution published. BLOCKS while
    /// another resolution of the same key is in flight — that block IS the fix: it is one thread
    /// waiting on one `dlopen` instead of two threads making each other's `dlopen` slower.
    ///
    /// Takes the registry the key was computed over so the entry can hold it WEAKLY — see
    /// [`Entry::registry`]: that handle is what stops a dead registry's address being reissued to a
    /// different registry, which is what makes the key's registry half mean "this registry".
    pub(super) fn admit(
        key: u64,
        registry: &std::sync::Arc<busbar_plugin_loader::PluginRegistry>,
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

    /// Is a resolution for `key` PUBLISHED right now? The observable readiness signal a caller can
    /// poll on, rather than betting a wall clock on the dynamic linker.
    #[cfg(test)]
    pub(super) fn published(key: u64) -> bool {
        let (lock, _) = state();
        let inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.get(&key).is_some_and(|e| e.value.is_some())
    }

    /// Is a resolution for `key` STILL RUNNING? Tells a caller whose deadline elapsed apart from one
    /// whose hook genuinely does not resolve — the same `None` reaches both.
    #[cfg(test)]
    pub(super) fn in_flight(key: u64) -> bool {
        let (lock, _) = state();
        let inner = lock.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.get(&key).is_some_and(|e| e.in_flight)
    }

    /// Drop published entries oldest-first until at most [`CAP`] remain. An in-flight claim is never
    /// evicted (its `Entry` is the claim's own bookkeeping).
    ///
    /// Entries whose REGISTRY IS GONE go first, and unconditionally — not just when over cap. Such
    /// an entry can never be hit again (the key names a registry nothing can hold any more), and it
    /// is pinning both a plugin image and the dead registry's `Arc` allocation for nothing. This is
    /// the reclaim half of the `Weak` in [`Entry::registry`]: the pin makes the address unreusable,
    /// and this makes the pin end at the first eviction pass after a `plugins refresh` rather than
    /// at [`CAP`] resolutions later.
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
                break; // everything left is in flight; nothing is evictable
            };
            evicted.extend(inner.entries.remove(&oldest));
        }
        // Handed back rather than dropped here ON PURPOSE: dropping the last `Arc` to a transport
        // UNLOADS the plugin library, and doing that while holding the admission lock would stall
        // every other hook's resolution behind a `dlclose`.
        evicted
    }
}

/// The configure-push deadline (spec `configure_timeout_ms` default): distinct from the
/// per-request gate deadline — configure may do real work (reload a model, open files).
const CONFIGURE_TIMEOUT_MS: u64 = 5000;

/// PUSH a settings map to a hook over its transport and wait for the ack (the
/// `PATCH /api/v1/admin/hooks/{name}/settings` core). `Ok` = acked (commit); `Err` = NOT committed.
pub(crate) async fn push_configure(
    hook: &crate::config::HookCfg,
    name: &str,
    settings_version: u64,
    env: &HookEnv,
) -> Result<(), String> {
    // ONE offloaded step resolves the SecretRefs AND opens the transport (ADR-0010: an unresolvable
    // ref is FAIL-CLOSED, so the plugin never receives a dangling reference on a settings push).
    //
    // The resolution used to happen HERE, inline, one line above this call — a synchronous FFI call
    // into a `kind: secret` plugin (a Vault/AWS-SM round trip) on a Tokio worker inside an `async
    // fn`, with no `spawn_blocking`, no in-flight bound, and NO DEADLINE (`CONFIGURE_TIMEOUT_MS`
    // applies only to the `configure` below). Concurrent admin pushes against a slow secret store
    // parked one worker each until the runtime polled nothing. `gate_transport_named` already
    // resolves the bag to build its `cfg_json`, so taking it from there removes the second
    // resolution rather than offloading it twice.
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

/// The deadline for RESOLVING a hook transport. `gate_transport_named` stages a copy of the plugin
/// to disk, `dlopen`s it and runs its constructor; none of that is cancellable, so this bounds the
/// CALLER, not the work — the alternative is a control-plane request that never returns and a
/// `/metrics/hooks` slot that is never freed for the life of the process.
///
/// A timed-out `spawn_blocking` thread is still abandoned, but abandoning it no longer WASTES it:
/// it holds the [`resolution`] claim for its key, so nothing queues a second `dlopen` behind it, and
/// it publishes when it lands, so the next caller adopts the result instead of starting over.
const TRANSPORT_RESOLVE_TIMEOUT_MS: u64 = CONFIGURE_TIMEOUT_MS;

/// EVERY control-plane deadline in this module goes through here, and it applies the caller's
/// number VERBATIM — in every build, test binaries included. The funnel is kept because
/// `push_configure` awaits two deadlines in sequence and a change that reached one and not the other
/// would read exactly like a change that reached both; it is no longer a place where the value can
/// fork.
///
/// **This used to return 60 s under `cfg(test)` and that fork is deleted, not relocated.** It was a
/// mitigation for `dlopen_configure_acks_exact_version` and `dlopen_status_and_schema_reads` failing
/// about one run in three under `--workspace`, and it did not work, because the premise was wrong:
/// the resolve was not "milliseconds on a machine doing normal work" that occasional load pushed
/// past 5 s. Timed, it was a median of **5.9 s and a worst case of 88 s** across a full workspace
/// run — past 60 s as comfortably as past 5 s. The cause was the engine opening a fresh `dlopen`ed
/// image on every control-plane touch against a process-globally serialised linker (see
/// [`resolution`]); with that closed, the production 5 s is a real bound again and the tests hold it.
fn applied_deadline(ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms)
}

/// Run a blocking closure with a deadline, collapsing "ran out of time" and "panicked" into the same
/// `None` the caller already treats as "unresolvable" — but LOGGING each distinctly first, so a
/// panicking plugin constructor (a security gate silently disarmed) is no longer indistinguishable
/// from an ordinary absent-transport `None`. Pure so the bound is unit-testable without a live
/// plugin (the same justification `response_len_ok` gives for its own shape).
async fn offload_bounded<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    offload_bounded_with_deadline(what, applied_deadline(TRANSPORT_RESOLVE_TIMEOUT_MS), f).await
}

/// The testable core of [`offload_bounded`]: `spawn_blocking` runs the closure on a REAL OS thread,
/// so a paused-clock test runtime cannot make a genuinely-sleeping closure return early (auto-advance
/// only fires while the runtime is idle, and a live blocking thread never reports idle). Taking the
/// deadline as a parameter lets a test use a real but SHORT deadline instead, so the timeout arm is
/// exercised deterministically in well under a second rather than needing paused time to work around
/// real blocking-thread sleep.
async fn offload_bounded_with_deadline<T: Send + 'static>(
    what: &str,
    deadline: std::time::Duration,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    let task = tokio::task::spawn_blocking(f);
    match tokio::time::timeout(deadline, task).await {
        Ok(Ok(v)) => v,
        // The blocking task PANICKED. Distinct from "no resolvable transport", which is what the
        // swallowed JoinError used to look like: a panicking plugin constructor silently disarmed a
        // gate. The two EXPECTED failures already warn inside `gate_transport_named`.
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

/// Resolve a hook's control-plane transport WITHOUT parking a Tokio worker.
///
/// [`gate_transport_named`] is not cheap and it is not async: it resolves secrets, WRITES A STAGING
/// COPY of the plugin to disk, `dlopen`s it, and runs the plugin's constructor. Every one of those
/// is synchronous filesystem / dynamic-linker work, and every control-plane read below used to do it
/// inline on the reactor -- so a slow disk or a slow plugin constructor stalled request serving, on
/// a path (`GET /metrics/hooks`) that a monitoring system hits on a fixed interval forever.
///
/// One offload site for all three readers, so a fourth cannot reintroduce the inline form by
/// calling `gate_transport_named` from an `async fn`.
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

/// THE READINESS SIGNAL for a hook's control-plane transport: block until the loader has PUBLISHED a
/// resolution for this exact hook, then leave it published for the caller under test to consume.
///
/// This exists because a test that asserts on a `configure` ack must not also be asserting that a
/// `dlopen` finished inside 5 s on whatever machine CI gave it. The honest way to stop that second,
/// unintended assertion is NOT a bigger number — [`applied_deadline`] records what happened when
/// that was tried — it is to wait on something observable. [`resolution::published`] is that
/// something: it is true exactly when the load this test needs has actually completed.
///
/// It is a BOUNDED loop with a REAL predicate, and it never widens a deadline. Each attempt runs at
/// the production 5 s; an attempt that overruns it does not restart the load, because the claim in
/// [`resolution::admit`] is held across the load and the overrunning thread publishes when it lands
/// — so the next attempt either finds the value published or waits on the one already in flight.
/// The attempt count is a HANG DETECTOR, not a budget: if the loader genuinely never publishes,
/// failing with a message that says so beats a test that never returns.
///
/// `false` means the hook resolved to nothing (an unloadable plugin) or is not eligible for
/// publication at all — a hook carrying a `SecretRef` is resolved fresh every time by design, so
/// there is no readiness to wait on and the caller should just proceed.
#[cfg(test)]
pub(crate) async fn await_transport_published(
    name: &str,
    hook: &crate::config::HookCfg,
    env: &HookEnv,
) -> bool {
    /// Enough attempts that only a genuine hang exhausts them (each attempt is bounded by the
    /// production resolve deadline).
    const ATTEMPTS: usize = 24;
    let Some(key) = resolution::key(name, hook, env) else {
        return false;
    };
    for _ in 0..ATTEMPTS {
        if resolution::published(key) {
            return true;
        }
        if gate_transport_offloaded(name, hook, env, 0).await.is_some() {
            // Resolved inside the deadline; `gate_transport_named` published it on the way through.
            return resolution::published(key);
        }
        // `None` is two different things and only one of them is worth waiting for: a load still
        // running (the caller's deadline elapsed, the claim is still held) versus a hook that
        // genuinely does not resolve.
        if !resolution::in_flight(key) {
            return false;
        }
    }
    panic!(
        "the loader never published a transport for hook '{name}' after {ATTEMPTS} resolve \
         attempts; that is a HANG in plugin resolution, not a slow machine"
    );
}

/// Fetch a hook's self-reported STATUS (observed settings + metrics) over its transport — the
/// control-plane read behind `GET /api/v1/admin/hooks/{name}/status`. Its own transport, never the
/// hot request path's (that one is resolved at boot and lives in the routing chain); `None` =
/// unsupported/unreachable (fail-open). The transport is shared with the other control-plane
/// readers of the SAME hook+settings+registry and no further — see [`resolution`], and note in
/// particular that a hook carrying a `SecretRef` is still resolved fresh on every one of these
/// reads, so a rotated credential is picked up on the next scrape exactly as before.
pub(crate) async fn fetch_status(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<busbar_api::HookStatus> {
    let (transport, _resolved) =
        gate_transport_offloaded(name, hook, env, settings_version).await?;
    transport
        .status(applied_deadline(CONFIGURE_TIMEOUT_MS))
        .await
}

/// The DESIRED settings KEY NAMES whose value the hook is not actually running — the whole of what
/// `GET /api/v1/admin/hooks/{name}/status` reports about settings drift, and the only thing about it
/// that may leave this function.
///
/// TWO PROBLEMS ARE CLOSED HERE, and they are the same problem seen from two sides.
///
/// 1. NEITHER BAG MAY GO ON THE WIRE. The endpoint used to serialize `reported.settings` verbatim,
///    which is the hook's ECHO of the SECRET-RESOLVED bag: `configure_hook` pushes
///    `resolve_hook_settings(&hook.settings)`, so the plugin receives — and echoes back — the
///    PLAINTEXT of every `SecretRef`. That is resolved secret material, at READ-ONLY admin scope.
///    So the comparison happens in here rather than at the endpoint, and the caller gets
///    KEY NAMES (which it is already free to serve) and a boolean.
/// 2. A `SecretRef` FIELD MUST NOT REPORT DRIFT ON EVERY POLL. The comparison ran the reported
///    (resolved) values against `hook.settings` (UNRESOLVED), so any `SecretRef` field drifted
///    forever — a permanent false positive that trains an operator to ignore the one signal this
///    endpoint exists to raise. Such a field is now simply NOT COMPARED: its desired value is a
///    reference, its observed value is that reference's plaintext, and the two are not comparable
///    without resolving. "Cannot compare" is reported as "not drifted", which is the same
///    fail-open posture the rest of this function already takes.
///
/// NO SECRET RESOLUTION HAPPENS HERE, DELIBERATELY. This runs on an async admin GET that a
/// dashboard polls (5s is typical). Resolving the desired bag — the first shape of this fix — made
/// that GET call `SecretResolver::resolve`, whose non-built-in arm is a SYNCHRONOUS FFI call into a
/// `kind: secret` plugin, inline on a Tokio worker with no `spawn_blocking` and no cache: a Vault
/// round-trip per poll, a worker parked for the plugin's full timeout whenever Vault is slow, and a
/// `tracing::info!` naming the setting and its reference on every single call.
/// `run_chain_on_request_path`'s own doc describes exactly this hazard and offloads for it. So the
/// classification is done by SHAPE instead (`config::secret::classify_setting` — the same
/// classifier `resolve_settings` uses, so the two cannot drift about what a reference is), which
/// reads nothing and calls nothing.
///
/// Semantics are otherwise unchanged: ordinary fields (including a `{ literal: … }` escape hatch,
/// unwrapped exactly as the configure push unwraps it) are compared value-for-value, only DESIRED
/// keys are compared (extra self-managed keys the hook reports are not drift), and a hook that
/// reports no settings at all is not drift (it may simply not implement the echo).
pub(crate) fn settings_drift_keys(
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
            // A reference's desired value is unknowable without I/O, so it is never drift.
            crate::config::secret::SettingShape::Reference(_) => false,
            crate::config::secret::SettingShape::Verbatim(want) => observed.get(*k) != Some(want),
        })
        .map(|(k, _)| k.clone())
        .collect();
    keys.sort();
    keys
}

/// Fetch a hook's self-described settings schema over its transport
/// (`GET /api/v1/admin/hooks/{name}/schema`). `None` = the hook/transport doesn't answer describe.
pub(crate) async fn fetch_schema(
    name: &str,
    hook: &crate::config::HookCfg,
    settings_version: u64,
    env: &HookEnv,
) -> Option<serde_json::Value> {
    let (transport, _resolved) =
        gate_transport_offloaded(name, hook, env, settings_version).await?;
    // `DlopenPolicy::describe` returns the schema member ALREADY EXTRACTED from the plugin's
    // self-description envelope (via the `describe_schema` projector), so the /schema read serves a
    // SINGLE nest (the endpoint adds its own {name, schema} wrapper). No schema member (incl. the
    // `{}` unsupported reply) = no schema (the endpoint reports null).
    transport
        .describe(applied_deadline(CONFIGURE_TIMEOUT_MS))
        .await
}

/// Resolve a hook's `on_error` NAME into its runtime fallback chain + terminal, following the
/// registry: a reserved terminal stops immediately (the common, zero-cost case); a built-in ranking
/// strategy appends one infallible link and terminates (its abstain converges with weighted);
/// another GATE appends its transport and the walk continues through ITS `on_error`. Boot
/// validation is the loud gate for unknown names / taps / cycles — here they degrade safely to the
/// weighted terminal (never a stranded request), with a visited guard so a cycle cannot loop.
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
        // A built-in ranking strategy: sync, no I/O, cannot fail — one link, then done. Compiled
        // out, the name falls through to the registry lookup below (and validation errored at boot).
        #[cfg(feature = "hooks-ranking")]
        if let Some(policy) = busbar_hooks_ranking::native_policy(current) {
            chain.push(FallbackHook {
                policy,
                timeout: policy_timeout(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
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

/// A gate's `on_empty` behavior (empty restrict intersection): the configured value, or the
/// FAIL-CLOSED default `Reject` — the spec default for a compliance restrict, never allow-all.
fn gate_on_empty(hook: &crate::config::HookCfg) -> crate::config::PolicyOnError {
    hook.on_empty
        .clone()
        .unwrap_or(crate::config::PolicyOnError::Reject)
}

/// Resolve the GLOBAL rewrite hooks — the `global_hooks` names whose registry entry is a `kind: gate`
/// with a `prompt: rw` grant — into their transports, sorted by ASCENDING `priority` (the transform
/// chain order; `weighted`-tie-break by config order is preserved by the stable sort). Returns
/// `(per-hook transform deadline, transport)` pairs. The `rw` GRANT IS ENFORCED HERE: a `ro`/`no`
/// gate (or a tap, or a non-rewrite gate) is skipped, so it can never rewrite — the bidirectional
/// grant holds by construction, independent of what a hook tries to return. A genuinely-absent
/// plugin is skipped (fail-open safety net); an `open()`-time FAILURE of a present rewrite gate is
/// caught by `HookEnv::preopen_gate_hooks`, which aborts boot/reload (so a redaction/rewrite gate
/// can never silently vanish while boot succeeds).
pub(crate) fn resolve_rewrite_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> {
    let mut ranked: Vec<(u16, std::time::Duration, Arc<dyn RoutingPolicy>)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        // EFFECTIVE rw, not the operator grant: the grant alone would admit a plugin whose manifest
        // declared `needs: { prompt: no }` to both read the prompt and rewrite the body.
        if hook.kind != crate::config::HookKind::Gate || !admits_rewrite(name, hook, env) {
            continue;
        }
        if let Some(ResolvedPolicy::Policy {
            policy, timeout, ..
        }) = resolve_gate_transport(name, hook, hooks, env, settings_version)
        {
            ranked.push((hook.priority, timeout, policy));
        }
    }
    ranked.sort_by_key(|(p, _, _)| *p);
    ranked.into_iter().map(|(_, t, p)| (t, p)).collect()
}

/// A resolved GLOBAL (all-pools) tap: `(per-hook deadline, prompt-grant, transport, caller-group
/// scope)`. The 4th element is the hook's `groups:` SELECTION scope (1.5.3) — the firing site fires
/// the tap only for a caller in that scope (empty = every caller); see [`TapEntry`] consumers in
/// `proxy::engine` / `proxy::hooks`.
pub(crate) type TapEntry = (
    std::time::Duration,
    bool,
    Arc<dyn RoutingPolicy>,
    Vec<String>,
);

/// Resolve the GLOBAL TAP hooks observing at ONE stage — the all-pools (`global_hooks`) names whose
/// registry entry is a `kind: tap` firing at `stage` (per its `phase:` list / legacy `at:`) — into
/// their transports. Returns [`TapEntry`] tuples carrying each tap's `groups:` scope for the
/// request-time caller filter. Taps are fire-and-forget so order is irrelevant, but a stable priority
/// sort keeps startup deterministic. Unresolvable transports are skipped (config_validate surfaces
/// them at boot).
pub(crate) fn resolve_tap_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
    stage: crate::config::HookStage,
) -> Vec<TapEntry> {
    let mut ranked: Vec<(u16, TapEntry)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        if hook.kind != crate::config::HookKind::Tap {
            continue;
        }
        // 1.5.3: the `phase:` LIST is authoritative when set; otherwise the legacy single `at:`
        // (defaulting to the request stage). A tap fires at this stage iff its phase set includes it.
        if !hook.fires_at_stage(stage) {
            continue;
        }
        // `send_prompt` carries the tap's `prompt: ro` grant through to the firing site, so a granted
        // tap gets the prompt content projection and a `prompt: no` (default) tap gets shape-only.
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

/// Resolve the GLOBAL DECISION gates — the `global_hooks` names whose registry entry is a `kind: gate`
/// that is NOT a rewrite gate (`prompt: rw` gates fire in the phase-1 transform pass via
/// `resolve_rewrite_hooks`; taps observe, they don't decide). These fire on EVERY request to reach a
/// verdict (reject / restrict / order) alongside a pool's own `hook:` gate. Returns the full
/// `ResolvedPolicy` for each (carrying `on_error`/`on_empty`/grants) so the firing site can run it
/// through the same `decide_policy_order` machinery as a pool gate, PLUS the hook's `priority` so
/// the firing site can merge globals with a pool's own gates into one phase-2 chain. Sorted by
/// ascending `priority` (the chain tie-break, e.g. which reject message surfaces). A genuinely-absent
/// plugin is skipped (fail-open safety net); an `open()`-time FAILURE of a present decision gate is
/// caught by `HookEnv::preopen_gate_hooks`, which aborts boot/reload (so a Reject/restrict gate can
/// never silently vanish while boot reports success).
pub(crate) fn resolve_gate_hooks(
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: &[String],
    env: &HookEnv,
    settings_version: u64,
) -> Vec<(u16, ResolvedPolicy)> {
    let mut ranked: Vec<(u16, ResolvedPolicy)> = Vec::new();
    for name in global_hooks {
        let Some(hook) = hooks.get(name) else {
            continue;
        };
        // Decision gates only: a gate that does not rewrite. `rw` gates are phase-1 rewrites; taps
        // never decide. (A gate may still return nothing/reject/restrict/order.)
        if hook.kind != crate::config::HookKind::Gate || hook.prompt.can_rewrite() {
            continue;
        }
        if let Some(rp) = resolve_gate_transport(name, hook, hooks, env, settings_version) {
            ranked.push((hook.priority, rp));
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    ranked
}

/// THE ADDITIVE-LIST COMBINE RULE, stated once for every plane that has one.
///
/// A section-level attach (`pools.hooks:` / `tools.hooks:` / `agents.hooks:`) and an entry's own
/// `hooks:` are a LIST, and a LIST combines ADDITIVELY: section first, then the entry's own, deduped
/// by name so a hook named in both fires ONCE, at its first (section) position.
///
/// Written here rather than once per plane because it is a rule of the CONFIG GRAMMAR, not of any
/// plane — and because two copies of it is exactly how the section list and an entry list come to
/// dedupe differently on one plane and not the other.
pub(crate) fn attach_list(section: &[String], own: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(section.len() + own.len());
    for h in section.iter().chain(own) {
        if !out.iter().any(|e| e == h) {
            out.push(h.clone());
        }
    }
    out
}

/// Resolve the per-CONTAINER gate chains for one plane's registry: for each `(container name, that
/// container's own hook list)`, the effective attach ([`attach_list`]) resolved through
/// [`resolve_gate_hooks`], keyed by container.
///
/// A container whose effective chain is EMPTY gets NO ENTRY, deliberately: the firing site's lookup
/// then answers `None` on every deployment that attached nothing, which is the zero-cost default,
/// and an empty vector in the map would make "attached nothing" and "attached something that did not
/// resolve" indistinguishable at a glance.
///
/// Called ONCE per config generation, from the App build. Resolution `dlopen`s the plugin; doing it
/// per request would put a library load on a dispatch path.
pub(crate) fn resolve_container_gates<'a>(
    containers: impl Iterator<Item = (&'a str, &'a [String])>,
    section: &[String],
    hooks: &std::collections::HashMap<String, crate::config::HookCfg>,
    env: &HookEnv,
    settings_version: u64,
) -> std::collections::HashMap<String, Vec<(u16, ResolvedPolicy)>> {
    let mut out = std::collections::HashMap::new();
    for (name, own) in containers {
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

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
