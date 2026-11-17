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
use crate::off_path::hooks::{gate_on_empty, inherited_ordering, policy_timeout};

use super::hooks::{CallerKey, HookRead};
use super::port_hooks::{Binder, Call, Selected, Selection, Taps};

/// One S8-opened instance; `image` keys the frozen admitted word catalog. The root obtains both
/// identity and words from that instance's admitted descriptor, never from its settings.
pub struct OpenedHook {
    pub port: Arc<dyn HookPort>,
    pub image: Arc<str>,
    pub words: Vec<Box<str>>,
    /// The actual dispatcher call budget, capped by this opened instance's final limits.
    pub timeout: std::time::Duration,
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
    tables: Tables,
    groups: BTreeMap<String, crate::config::groups::GroupCfg>,
    governance: Arc<GovState>,
    cost: Arc<CostModel>,
    amendments: Arc<NodeAmendments>,
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
        if scope.section.is_empty() || scope.pool.as_ref().is_some_and(String::is_empty) {
            return Err(
                "native hook seat requires nonempty configured section and pool names".into(),
            );
        }
        let section = cfg
            .plane_defs
            .get(scope.section.as_str())
            .map(|s| s.container_gates());
        if let Some(section) = &section {
            if let Some((container, hooks)) = section.containers.iter().find(|(_, h)| !h.is_empty())
            {
                return Err(format!(
                    "native seat `{}` cannot bind container `{container}` hook attachment `{}`: no configured container authority",
                    scope.section, hooks.join(", ")
                ));
            }
        }
        let calls = Calls {
            hooks: &cfg.hooks,
            opened,
            words,
        };
        let section_names = section
            .as_ref()
            .map_or(&[][..], |s| s.section_hooks.as_slice());
        let default_pool = crate::config::PoolCfg::default();
        let pool = scope
            .pool
            .as_ref()
            .map(|p| cfg.pools.get(p).unwrap_or(&default_pool));
        let tables = Tables::build(&calls, &cfg.global_hooks, section_names, pool)
            .map_err(|why| format!("native seat `{}`: {why}", scope.section))?;
        if tables.active() && scope.routes.is_empty() {
            return Err(format!(
                "native seat `{}` has hook attachments but no admitted routes",
                scope.section
            ));
        }
        if scope.routes.iter().copied().collect::<BTreeSet<_>>().len() != scope.routes.len() {
            return Err(format!(
                "native seat `{}` has duplicate admitted route ids",
                scope.section
            ));
        }
        Ok(Self {
            billing_pool: format!("{}{}", scope.section, crate::governance::PLANE_LANE_SEP),
            scope,
            tables,
            groups: cfg.groups.clone(),
            governance,
            cost,
            amendments,
        })
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
        let selected = self
            .tables
            .select(group, &self.groups, !input.pool.is_empty());
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
            signals.insert(signal);
        }
        Ok(Call {
            name: Arc::from(name),
            port: opened.port.clone(),
            timeout: policy_timeout(hook.timeout_ms),
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
        for (name, hook) in crate::off_path::hooks::decision_definitions(calls.hooks, names) {
            out.gates.push(Bound::new(
                calls.named(name, POINT_ROUTE)?,
                Some(hook),
                calls.hooks,
            ));
        }
        for (name, hook) in
            crate::off_path::hooks::rewrite_definitions(calls.hooks, names, |_, h| {
                h.prompt.can_rewrite()
            })
        {
            out.rewrites.push(Bound::new(
                calls.named(name, POINT_REWRITE)?,
                Some(hook),
                calls.hooks,
            ));
        }
        for &stage in crate::config::hooks::CORE_HOOK_PHASES {
            for (name, hook) in crate::off_path::hooks::tap_definitions(calls.hooks, names, stage) {
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

struct Tables {
    global: Attached,
    section: Attached,
    pool: Attached,
    policy: Option<Bound>,
}
struct Chosen {
    rewrites: Vec<Arc<Call>>,
    gates: Vec<Arc<Call>>,
    policy: Option<Arc<Call>>,
    taps: Taps,
}

impl Tables {
    fn build(
        calls: &Calls<'_>,
        global: &[String],
        section: &[String],
        pool: Option<&crate::config::PoolCfg>,
    ) -> Result<Self, String> {
        let defaults = calls
            .hooks
            .iter()
            .filter(|(_, h)| h.default)
            .collect::<Vec<_>>();
        if defaults.len() > 1 {
            return Err(format!(
                "several default hook bindings: {}",
                defaults
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let default = defaults.first().map(|(name, _)| name.as_str());
        if let Some((name, hook)) = defaults.first() {
            if hook.kind != HookKind::Gate || hook.prompt.can_rewrite() {
                return Err(format!(
                    "default hook attachment `{name}` cannot represent a base routing policy"
                ));
            }
        }
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
        Ok(Self {
            global: Attached::build(calls, global)?,
            section: Attached::build(calls, section)?,
            pool: Attached::build(calls, pool.map_or(&[][..], |p| p.gates.as_slice()))?,
            policy,
        })
    }
    fn active(&self) -> bool {
        self.global.active() || self.section.active() || self.pool.active() || self.policy.is_some()
    }
    fn enforcing(&self) -> bool {
        self.global.enforcing()
            || self.section.enforcing()
            || self.pool.enforcing()
            || self.policy.is_some()
    }
    fn select(
        &self,
        group: Option<&str>,
        tree: &BTreeMap<String, crate::config::groups::GroupCfg>,
        with_pool: bool,
    ) -> Chosen {
        let mut rewrites = Vec::new();
        let mut gates = Vec::new();
        let mut taps = Taps::default();
        for attached in [&self.global, &self.section]
            .into_iter()
            .chain(with_pool.then_some(&self.pool))
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
        Chosen {
            rewrites,
            gates: gates.into_iter().map(|(_, c)| c).collect(),
            taps,
            policy: self
                .policy
                .as_ref()
                .filter(|_| with_pool)
                .and_then(|b| b.select(group, tree)),
        }
    }
}

#[cfg(test)]
#[path = "native_hook_bindings/tests/construction.rs"]
mod tests;
