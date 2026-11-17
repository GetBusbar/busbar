// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native hook assembly over already-opened ports and admitted descriptors. Nothing in this
//! snapshot owns an App, serving generation, loader, or mutable publication slot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_plugin_abi::kinds::hook::hook::{
    FB_WANTS_PROMPT, POINT_NOTIFY, POINT_REWRITE, POINT_ROUTE,
};
use busbar_ports::hook::HookPort;

use crate::audit::amend::NodeAmendments;
use crate::config::hooks::HookRegistry;
use crate::config::{HookCfg, HookKind, HookStage, PolicyOnError, RootCfg};
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::hooks::RequestedSignals;

use super::hooks::{CallerKey, HookRead};
use super::port_hooks::{Binder, Call, RouteCounters, Selected, Selection, Taps};

/// One S8-opened instance; `image` keys the frozen admitted word catalog. The root obtains both
/// identity and words from that instance's admitted descriptor, never from its settings.
pub struct OpenedHook {
    pub port: Arc<dyn HookPort>,
    pub image: Arc<str>,
    pub words: Vec<Box<str>>,
    /// The actual dispatcher call budget, capped by this opened instance's final limits.
    pub timeout: std::time::Duration,
}

/// Resolve implicit strategy opens before S8, using only the actual seat's attachment roots and
/// pools. `configured` maps configured hook names to admitted image identities; `words` includes
/// every admitted hook image, even those that have not been opened. The root opens each returned
/// instance with empty settings through normal schema, Needs and limit admission.
pub fn implicit_strategies(
    hooks: &HookRegistry,
    attachments: &[String],
    pools: &[&crate::config::PoolCfg],
    configured: &BTreeMap<String, String>,
    words: &BTreeMap<String, Vec<Box<str>>>,
) -> Result<BTreeMap<String, String>, String> {
    let configured = hooks
        .keys()
        .map(|name| {
            configured
                .get(name)
                .map(|image| (name.as_str(), image.as_str()))
                .ok_or_else(|| {
                    format!("hook `{name}` has no admitted image for strategy resolution")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let words = words
        .iter()
        .map(|(image, words)| (image.as_str(), words.iter().map(AsRef::as_ref).collect()))
        .collect::<Vec<_>>();
    let default = default_hook(hooks)?;
    let mut roots = attachments
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut strategies = BTreeSet::new();
    for pool in pools {
        roots.extend(pool.gates.iter().map(String::as_str));
        if let Some((name, _)) = inherited_ordering(pool, hooks, default) {
            roots.insert(name);
        } else if let Some(word) = pool.policy.native_name() {
            strategies.insert(word);
        }
    }
    for name in roots {
        let hook = hooks
            .get(name)
            .ok_or_else(|| format!("hook attachment `{name}` has no definition"))?;
        if hook.kind == HookKind::Tap {
            continue;
        }
        let mut seen = BTreeSet::from([name]);
        let mut current = hook.on_error.as_str();
        while crate::config::on_error_terminal(current).is_none() {
            if !seen.insert(current) {
                return Err(format!(
                    "hook attachment `{name}` has a fallback cycle at `{current}`"
                ));
            }
            let Some(fallback) = hooks.get(current) else {
                if hook.prompt.can_rewrite() {
                    return Err(format!(
                        "hook attachment `{name}` fallback `{current}` cannot serve rewrite point"
                    ));
                }
                strategies.insert(current);
                break;
            };
            if fallback.kind != HookKind::Gate {
                return Err(format!(
                    "hook attachment `{name}` fallback `{current}` is not a gate"
                ));
            }
            current = &fallback.on_error;
        }
    }
    let mut implicit = BTreeMap::new();
    for word in strategies {
        let binding = crate::hooks::strategy::resolve_strategy(word, &configured, &words)
            .map_err(|why| why.0)?;
        if binding.implicit {
            // resolve_strategy has already proved exactly one admitted image declares this word.
            let image = words
                .iter()
                .find(|(_, declared)| declared.contains(&word))
                .map(|(image, _)| *image)
                .ok_or_else(|| format!("strategy `{word}` lost its admitted image"))?;
            implicit.insert(binding.instance.into_string(), image.to_owned());
        }
    }
    Ok(implicit)
}

fn default_hook(hooks: &HookRegistry) -> Result<Option<&str>, String> {
    let defaults = hooks
        .iter()
        .filter(|(_, hook)| hook.default)
        .collect::<Vec<_>>();
    if defaults.len() > 1 {
        return Err(format!(
            "several default hook bindings: {}",
            defaults
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some((name, hook)) = defaults.first() {
        if hook.kind != HookKind::Gate || hook.prompt.can_rewrite() {
            return Err(format!(
                "default hook attachment `{name}` cannot represent a base routing policy"
            ));
        }
    }
    Ok(defaults.first().map(|(name, _)| name.as_str()))
}

/// Root-projected authority from one instance's admitted registration and catalog plans.
/// A direct model deliberately has no pool policy to inherit or named-pool gates to execute.
pub enum WalkBinding {
    Registration {
        pool: String,
        config: crate::config::PoolCfg,
    },
    NamedPool {
        name: String,
        config: crate::config::PoolCfg,
    },
    DirectModel {
        name: String,
    },
}

impl WalkBinding {
    fn scope(&self) -> (&str, &str) {
        match self {
            Self::Registration { pool, .. } => (pool, ""),
            Self::NamedPool { name, .. } => (name, name),
            Self::DirectModel { name } => ("", name),
        }
    }

    fn pool(&self) -> Option<&crate::config::PoolCfg> {
        match self {
            Self::Registration { config, .. } | Self::NamedPool { config, .. } => Some(config),
            Self::DirectModel { .. } => None,
        }
    }
}

/// Frozen attachment inputs shared by pre-open strategy planning and post-open table binding.
/// This pure plan does not authorize dispatch or construct an admitted monetary observation.
pub struct WalkPlan {
    global: Vec<String>,
    section: Vec<String>,
    walks: Vec<WalkBinding>,
}

impl WalkPlan {
    pub fn new(
        global: Vec<String>,
        section: Vec<String>,
        walks: Vec<WalkBinding>,
    ) -> Result<Self, String> {
        let mut scopes = BTreeSet::new();
        for walk in &walks {
            let (pool, container) = walk.scope();
            if pool.is_empty() && container.is_empty() {
                return Err("native hook walk requires a nonempty configured name".into());
            }
            if !scopes.insert((pool, container)) {
                return Err(format!(
                    "duplicate native hook walk pool `{pool}` container `{container}`"
                ));
            }
        }
        Ok(Self {
            global,
            section,
            walks,
        })
    }

    pub fn implicit_strategies(
        &self,
        hooks: &HookRegistry,
        configured: &BTreeMap<String, String>,
        words: &BTreeMap<String, Vec<Box<str>>>,
    ) -> Result<BTreeMap<String, String>, String> {
        let attachments = self
            .global
            .iter()
            .chain(&self.section)
            .cloned()
            .collect::<Vec<_>>();
        let pools = self
            .walks
            .iter()
            .filter_map(WalkBinding::pool)
            .collect::<Vec<_>>();
        implicit_strategies(hooks, &attachments, &pools, configured, words)
    }

    /// Freeze only attachment policy. Expanded runtime use additionally requires the sealed
    /// admitted-request observer; these tables never reconstruct its key, charge chain or scope.
    pub fn bind(
        &self,
        hooks: &HookRegistry,
        opened: &BTreeMap<String, OpenedHook>,
        words: &BTreeMap<String, Vec<Box<str>>>,
    ) -> Result<WalkTables, String> {
        let calls = Calls {
            hooks,
            opened,
            words,
        };
        let default = default_hook(hooks)?;
        let global = Attached::build(&calls, &self.global)?;
        let section = Attached::build(&calls, &self.section)?;
        let mut walks: BTreeMap<String, BTreeMap<String, PoolTable>> = BTreeMap::new();
        for walk in &self.walks {
            let (pool, container) = walk.scope();
            let table = PoolTable::build(&calls, pool, walk.pool(), default, [&global, &section])
                .map_err(|why| {
                format!("native hook walk pool `{pool}` container `{container}`: {why}")
            })?;
            walks
                .entry(pool.to_owned())
                .or_default()
                .insert(container.to_owned(), table);
        }
        Ok(WalkTables {
            global,
            section,
            walks,
        })
    }
}

/// The configured native seat and the one pool its actual egress walk can inspect and constrain.
/// Routes are the exact admitted PlanePort route ids. Native seats currently have no container
/// authority; a container attachment therefore refuses construction rather than disappearing.
pub struct SeatScope {
    pub section: String,
    pub routes: Vec<u32>,
    pub pool: Option<String>,
}

/// Complete per-seat policy, frozen before the driver or any tick worker is published.
pub struct Bindings {
    scope: SeatScope,
    billing_pool: String,
    tables: WalkTables,
    groups: BTreeMap<String, crate::config::groups::GroupCfg>,
    governance: Arc<GovState>,
    cost: Arc<CostModel>,
    amendments: Arc<NodeAmendments>,
}

/// Owned policy inputs captured before the candidate RootCfg is consumed by App construction.
/// Opened ports and candidate services are supplied only at the later binding step.
pub struct Inputs {
    section: String,
    pool: Option<String>,
    plan: WalkPlan,
    hooks: HookRegistry,
    groups: BTreeMap<String, crate::config::groups::GroupCfg>,
}

impl Inputs {
    pub fn capture(cfg: &RootCfg, section: String, pool: Option<String>) -> Result<Self, String> {
        if section.is_empty() || pool.as_ref().is_some_and(String::is_empty) {
            return Err(
                "native hook seat requires nonempty configured section and pool names".into(),
            );
        }
        let section_cfg = cfg
            .plane_defs
            .get(section.as_str())
            .map(|s| s.container_gates());
        if let Some(section_cfg) = &section_cfg {
            if let Some((container, hooks)) =
                section_cfg.containers.iter().find(|(_, h)| !h.is_empty())
            {
                return Err(format!(
                    "native seat `{}` cannot bind container `{container}` hook attachment `{}`: no configured container authority",
                    section, hooks.join(", ")
                ));
            }
        }
        let section_names = section_cfg
            .as_ref()
            .map_or(&[][..], |s| s.section_hooks.as_slice());
        let walks = pool
            .as_ref()
            .map(|pool| WalkBinding::Registration {
                pool: pool.clone(),
                config: cfg.pools.get(pool).cloned().unwrap_or_default(),
            })
            .into_iter()
            .collect();
        Ok(Self {
            section,
            pool,
            plan: WalkPlan::new(cfg.global_hooks.clone(), section_names.to_vec(), walks)?,
            hooks: cfg.hooks.clone(),
            groups: cfg.groups.clone(),
        })
    }

    pub fn bind(
        &self,
        routes: Vec<u32>,
        opened: &BTreeMap<String, OpenedHook>,
        words: &BTreeMap<String, Vec<Box<str>>>,
        governance: Arc<GovState>,
        cost: Arc<CostModel>,
        amendments: Arc<NodeAmendments>,
    ) -> Result<Bindings, String> {
        let tables = self
            .plan
            .bind(&self.hooks, opened, words)
            .map_err(|why| format!("native seat `{}`: {why}", self.section))?;
        if tables.active() && routes.is_empty() {
            return Err(format!(
                "native seat `{}` has hook attachments but no admitted routes",
                self.section
            ));
        }
        if routes.iter().copied().collect::<BTreeSet<_>>().len() != routes.len() {
            return Err(format!(
                "native seat `{}` has duplicate admitted route ids",
                self.section
            ));
        }
        Ok(Bindings {
            billing_pool: format!("{}{}", self.section, crate::governance::PLANE_LANE_SEP),
            scope: SeatScope {
                section: self.section.clone(),
                routes,
                pool: self.pool.clone(),
            },
            tables,
            groups: self.groups.clone(),
            governance,
            cost,
            amendments,
        })
    }
}

impl Bindings {
    pub fn build(
        cfg: &RootCfg,
        scope: SeatScope,
        opened: &BTreeMap<String, OpenedHook>,
        words: &BTreeMap<String, Vec<Box<str>>>,
        governance: Arc<GovState>,
        cost: Arc<CostModel>,
        amendments: Arc<NodeAmendments>,
    ) -> Result<Self, String> {
        Inputs::capture(cfg, scope.section, scope.pool)?.bind(
            scope.routes,
            opened,
            words,
            governance,
            cost,
            amendments,
        )
    }

    pub fn has_hooks(&self) -> bool {
        self.tables.active()
    }
}

impl Binder for Bindings {
    fn active(&self, route: u32) -> bool {
        self.scope.routes.contains(&route) && self.tables.active()
    }

    fn enforcing(&self, route: u32) -> bool {
        self.scope.routes.contains(&route) && self.tables.enforcing()
    }

    fn select(&self, input: &Selection<'_>) -> Result<Selected, &'static str> {
        if !self.scope.routes.contains(&input.route) {
            return Err("native hook route is outside the frozen seat");
        }
        if !input.container.is_empty() {
            return Err("native hook container has no configured authority");
        }
        if !input.pool.is_empty() && self.scope.pool.as_deref() != Some(input.pool) {
            return Err("native hook pool is outside the configured walk");
        }
        // The checked invocation supplies the exact admitted key used by native billing.
        // External identities can have synthesized keys that are not in GovState's cache.
        let key = input.key;
        let group = key.and_then(|k| k.group.as_deref());
        let selected =
            self.tables
                .select_scope(group, &self.groups, input.pool, input.container)?;
        let mut budget = key.map_or_else(Vec::new, |key| {
            self.governance.budget_state(&self.cost, key, input.now_s)
        });
        budget.retain(|b| b.pool.as_deref().is_none_or(|p| p == self.billing_pool));
        let rate_headroom = key.and_then(|key| {
            self.governance
                .rate_headroom(&self.cost, key, Some(&self.billing_pool), input.now_s)
        });
        let amendments = self.amendments.clone();
        let reads: HookRead = Arc::new(move |names, principal, dialect, identity| {
            let amendments = amendments.clone();
            Box::pin(async move {
                crate::audit::amend::hook_reads(&amendments, names, principal, dialect, identity)
                    .await
            })
        });
        Ok(Selected {
            rewrites: selected.rewrites,
            gates: selected.gates,
            policy: selected.policy,
            taps: selected.taps,
            key: key.map(|k| CallerKey {
                id: k.id.clone(),
                name: k.name.clone(),
            }),
            budget,
            rate_headroom,
            cost: self.cost.clone(),
            reads,
            counters: selected.counters,
        })
    }
}

struct Calls<'a> {
    hooks: &'a HookRegistry,
    opened: &'a BTreeMap<String, OpenedHook>,
    /// All admitted images, including unopened ones: required to detect ambiguous words.
    words: &'a BTreeMap<String, Vec<Box<str>>>,
}

impl Calls<'_> {
    fn port(&self, name: &str, point: u32) -> Result<&OpenedHook, String> {
        let opened = self
            .opened
            .get(name)
            .ok_or_else(|| format!("hook attachment `{name}` has no opened native port"))?;
        if opened.port.points() & (1 << point) == 0 {
            return Err(format!(
                "hook attachment `{name}` does not declare native point {point}"
            ));
        }
        if opened.timeout.is_zero() {
            return Err(format!(
                "hook attachment `{name}` has no bounded native call budget"
            ));
        }
        Ok(opened)
    }

    fn one(&self, name: &str, hook: &HookCfg, point: u32) -> Result<Call, String> {
        let opened = self.port(name, point)?;
        if point == POINT_REWRITE
            && (!hook.prompt.can_rewrite() || opened.port.facts() & FB_WANTS_PROMPT == 0)
        {
            return Err(format!(
                "hook attachment `{name}` cannot represent the granted rewrite"
            ));
        }
        let mut signals = RequestedSignals::default();
        for &signal in &hook.signals {
            if matches!(
                signal,
                crate::hooks::Signal::CandidateBreakerState
                    | crate::hooks::Signal::CandidateLatencyP95Ms
            ) {
                return Err(format!(
                    "hook attachment `{name}` requests signal `{}` with no native encoding",
                    signal.name()
                ));
            }
            signals.insert(signal);
        }
        Ok(Call {
            name: Arc::from(name),
            port: opened.port.clone(),
            timeout: policy_timeout(hook.timeout_ms).min(opened.timeout),
            prompt: hook.prompt,
            user: hook.user,
            signals,
            on_error: PolicyOnError::Weighted,
            on_empty: gate_on_empty(hook),
            fallbacks: Vec::new(),
            strategy: None,
        })
    }

    fn named(&self, name: &str, point: u32) -> Result<Arc<Call>, String> {
        let hook = self
            .hooks
            .get(name)
            .ok_or_else(|| format!("hook attachment `{name}` has no definition"))?;
        let mut call = self.one(name, hook, point)?;
        // Taps cannot affect control flow; their configured error disposition is never invoked.
        if hook.kind == HookKind::Tap {
            return Ok(Arc::new(call));
        }
        let mut seen = BTreeSet::from([name]);
        let mut current = hook.on_error.as_str();
        loop {
            if let Some(terminal) = crate::config::on_error_terminal(current) {
                call.on_error = terminal;
                return Ok(Arc::new(call));
            }
            if !seen.insert(current) {
                return Err(format!(
                    "hook attachment `{name}` has a fallback cycle at `{current}`"
                ));
            }
            let Some(fallback) = self.hooks.get(current) else {
                if point != POINT_ROUTE {
                    return Err(format!(
                        "hook attachment `{name}` fallback `{current}` cannot serve rewrite point"
                    ));
                }
                let strategy = self
                    .strategy(current)
                    .map_err(|e| format!("hook attachment `{name}` fallback `{current}`: {e}"))?;
                call.fallbacks.push(strategy);
                return Ok(Arc::new(call));
            };
            if fallback.kind != HookKind::Gate {
                return Err(format!(
                    "hook attachment `{name}` fallback `{current}` is not a gate"
                ));
            }
            call.fallbacks
                .push(Arc::new(self.one(current, fallback, point)?));
            current = &fallback.on_error;
        }
    }

    fn strategy(&self, word: &str) -> Result<Arc<Call>, String> {
        let configured = self
            .hooks
            .keys()
            .map(|name| {
                self.opened
                    .get(name)
                    .map(|opened| (name.as_str(), opened.image.as_ref()))
                    .ok_or_else(|| {
                        format!("hook `{name}` has no opened native port for strategy resolution")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let words = self
            .words
            .iter()
            .map(|(image, words)| (image.as_str(), words.iter().map(AsRef::as_ref).collect()))
            .collect::<Vec<_>>();
        let binding =
            crate::hooks::strategy::resolve_strategy(word, &configured, &words).map_err(|e| e.0)?;
        let opened = self.port(&binding.instance, POINT_ROUTE)?;
        if !opened.words.iter().any(|w| w.as_ref() == word)
            || !self
                .words
                .get(opened.image.as_ref())
                .is_some_and(|ws| ws.iter().any(|w| w.as_ref() == word))
        {
            return Err(format!(
                "strategy `{word}` opened instance `{}` does not carry its admitted word",
                binding.instance
            ));
        }
        let mut signals = RequestedSignals::default();
        signals.insert(crate::hooks::Signal::CandidateRouteCost);
        Ok(Arc::new(Call {
            name: Arc::from(binding.instance.as_ref()),
            port: opened.port.clone(),
            timeout: opened.timeout,
            prompt: crate::config::PromptAccess::No,
            user: crate::config::UserAccess::No,
            signals,
            on_error: PolicyOnError::Weighted,
            on_empty: PolicyOnError::Reject,
            fallbacks: Vec::new(),
            strategy: Some(Arc::from(word)),
        }))
    }
}

struct Bound {
    call: Arc<Call>,
    priority: u16,
    groups: Vec<String>,
    fallback_groups: Vec<Vec<String>>,
}

impl Bound {
    fn new(call: Arc<Call>, hook: Option<&HookCfg>, hooks: &HookRegistry) -> Self {
        let fallback_groups = call
            .fallbacks
            .iter()
            .map(|f| {
                hooks
                    .get(f.name.as_ref())
                    .map_or_else(Vec::new, |h| h.groups.clone())
            })
            .collect();
        Self {
            call,
            priority: hook.map_or(0, |h| h.priority),
            groups: hook.map_or_else(Vec::new, |h| h.groups.clone()),
            fallback_groups,
        }
    }

    fn select(
        &self,
        group: Option<&str>,
        tree: &BTreeMap<String, crate::config::groups::GroupCfg>,
    ) -> Option<Arc<Call>> {
        let allowed = |groups: &[String]| crate::config::caller_in_hook_groups(group, groups, tree);
        if !allowed(&self.groups) {
            return None;
        }
        if self.fallback_groups.iter().all(|groups| allowed(groups)) {
            return Some(self.call.clone());
        }
        let c = &self.call;
        Some(Arc::new(Call {
            name: c.name.clone(),
            port: c.port.clone(),
            timeout: c.timeout,
            prompt: c.prompt,
            user: c.user,
            signals: c.signals,
            on_error: c.on_error.clone(),
            on_empty: c.on_empty.clone(),
            strategy: c.strategy.clone(),
            fallbacks: c
                .fallbacks
                .iter()
                .zip(&self.fallback_groups)
                .filter(|(_, groups)| allowed(groups))
                .map(|(call, _)| call.clone())
                .collect(),
        }))
    }
}

#[derive(Default)]
struct Attached {
    rewrites: Vec<Bound>,
    gates: Vec<Bound>,
    taps: Vec<(HookStage, Bound)>,
}

impl Attached {
    fn build(calls: &Calls<'_>, names: &[String]) -> Result<Self, String> {
        let mut out = Self::default();
        // Validate every named attachment before role filtering; an unrepresentable name cannot
        // vanish through the legacy filter_map helpers.
        for name in names {
            if !calls.hooks.contains_key(name) {
                return Err(format!("hook attachment `{name}` has no definition"));
            }
        }
        for (name, hook) in decision_definitions(calls.hooks, names) {
            out.gates.push(Bound::new(
                calls.named(name, POINT_ROUTE)?,
                Some(hook),
                calls.hooks,
            ));
        }
        for (name, hook) in rewrite_definitions(calls.hooks, names, |_, h| h.prompt.can_rewrite()) {
            out.rewrites.push(Bound::new(
                calls.named(name, POINT_REWRITE)?,
                Some(hook),
                calls.hooks,
            ));
        }
        for &stage in crate::config::hooks::CORE_HOOK_PHASES {
            for (name, hook) in tap_definitions(calls.hooks, names, stage) {
                if hook.prompt.can_rewrite() {
                    return Err(format!(
                        "tap attachment `{name}` cannot receive a rewrite grant"
                    ));
                }
                out.taps.push((
                    stage,
                    Bound::new(calls.named(name, POINT_NOTIFY)?, Some(hook), calls.hooks),
                ));
            }
        }
        out.gates.sort_by_key(|b| b.priority);
        out.rewrites.sort_by_key(|b| b.priority);
        out.taps.sort_by_key(|(_, b)| b.priority);
        Ok(out)
    }
    fn active(&self) -> bool {
        self.enforcing() || !self.taps.is_empty()
    }
    fn enforcing(&self) -> bool {
        !self.rewrites.is_empty() || !self.gates.is_empty()
    }
}

/// Pure immutable attachment tables; this is not an expanded runtime Binder constructor.
pub struct WalkTables {
    global: Attached,
    section: Attached,
    walks: BTreeMap<String, BTreeMap<String, PoolTable>>,
}

struct PoolTable {
    attached: Attached,
    policy: Option<Bound>,
    /// Bound for a configured pool; a direct model has none.
    counters: Option<Arc<RouteCounters>>,
}
struct Chosen {
    rewrites: Vec<Arc<Call>>,
    gates: Vec<Arc<Call>>,
    policy: Option<Arc<Call>>,
    taps: Taps,
    counters: Option<Arc<RouteCounters>>,
}

impl PoolTable {
    /// `outer`: the global and section attachments, which decide this walk beside its own.
    fn build(
        calls: &Calls<'_>,
        label: &str,
        pool: Option<&crate::config::PoolCfg>,
        default: Option<&str>,
        outer: [&Attached; 2],
    ) -> Result<Self, String> {
        let policy = if let Some(pool) = pool {
            if let Some((name, hook)) = inherited_ordering(pool, calls.hooks, default) {
                Some(Bound::new(
                    calls.named(name, POINT_ROUTE)?,
                    Some(hook),
                    calls.hooks,
                ))
            } else if let Some(word) = pool.policy.native_name() {
                Some(Bound::new(calls.strategy(word)?, None, calls.hooks))
            } else {
                None
            }
        } else {
            None
        };
        let attached = Attached::build(calls, pool.map_or(&[][..], |p| p.gates.as_slice()))?;
        let counters = pool.map(|_| {
            let deciding = outer
                .into_iter()
                .chain([&attached])
                .flat_map(|a| a.rewrites.iter().chain(&a.gates))
                .chain(&policy)
                .map(|bound| &bound.call);
            Arc::new(RouteCounters::bind(label, deciding))
        });
        Ok(Self {
            attached,
            policy,
            counters,
        })
    }
    fn active(&self) -> bool {
        self.attached.active() || self.policy.is_some()
    }
    fn enforcing(&self) -> bool {
        self.attached.enforcing() || self.policy.is_some()
    }
}

impl WalkTables {
    pub fn active(&self) -> bool {
        self.global.active()
            || self.section.active()
            || self
                .walks
                .values()
                .flat_map(BTreeMap::values)
                .any(PoolTable::active)
    }

    pub fn enforcing(&self) -> bool {
        self.global.enforcing()
            || self.section.enforcing()
            || self
                .walks
                .values()
                .flat_map(BTreeMap::values)
                .any(PoolTable::enforcing)
    }

    fn select_scope(
        &self,
        group: Option<&str>,
        tree: &BTreeMap<String, crate::config::groups::GroupCfg>,
        pool: &str,
        container: &str,
    ) -> Result<Chosen, &'static str> {
        let selected = if pool.is_empty() && container.is_empty() {
            None
        } else {
            Some(
                self.walks
                    .get(pool)
                    .and_then(|walks| walks.get(container))
                    .ok_or("native hook scope is outside the configured walk")?,
            )
        };
        let mut rewrites = Vec::new();
        let mut gates = Vec::new();
        let mut taps = Taps::default();
        for attached in [&self.global, &self.section]
            .into_iter()
            .chain(selected.map(|pool| &pool.attached))
        {
            rewrites.extend(
                attached
                    .rewrites
                    .iter()
                    .filter_map(|b| b.select(group, tree)),
            );
            gates.extend(
                attached
                    .gates
                    .iter()
                    .filter_map(|b| b.select(group, tree).map(|c| (b.priority, c))),
            );
            for (stage, b) in &attached.taps {
                let Some(call) = b.select(group, tree) else {
                    continue;
                };
                match stage {
                    HookStage::Request => &mut taps.request,
                    HookStage::Candidate => &mut taps.candidate,
                    HookStage::Routing => &mut taps.routing,
                    HookStage::Response => &mut taps.response,
                }
                .push(call);
            }
        }
        gates.sort_by_key(|(priority, _)| *priority);
        Ok(Chosen {
            rewrites,
            gates: gates.into_iter().map(|(_, c)| c).collect(),
            taps,
            policy: selected
                .and_then(|pool| pool.policy.as_ref())
                .and_then(|b| b.select(group, tree)),
            counters: selected.and_then(|pool| pool.counters.clone()),
        })
    }
}

fn policy_timeout(timeout_ms: u64) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        crate::limits::default_policy_timeout_ms()
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms)
}

fn inherited_ordering<'a>(
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

fn decision_definitions<'a>(
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

fn tap_definitions<'a>(
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

fn rewrite_definitions<'a>(
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

fn gate_on_empty(hook: &crate::config::HookCfg) -> crate::config::PolicyOnError {
    hook.on_empty
        .clone()
        .unwrap_or(crate::config::PolicyOnError::Reject)
}

#[cfg(test)]
#[path = "native_hook_bindings/tests/construction.rs"]
mod tests;
