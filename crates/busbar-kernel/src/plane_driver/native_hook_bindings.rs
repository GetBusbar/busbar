// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native hook assembly over already-opened ports and admitted descriptors. Nothing in this
//! snapshot owns an App, serving generation, loader, or mutable publication slot.

//! The tables are resolved and frozen off the request path (`off_path::plane_native_hooks`); a
//! request only selects from them (`Binder for Bindings`).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_ports::hook::HookPort;

use crate::audit::amend::NodeAmendments;
use crate::config::hooks::HookRegistry;
use crate::config::HookStage;
use crate::cost::CostModel;
use crate::governance::GovState;

use super::hooks::{CallerKey, HookRead};
use super::port_hooks::{Binder, Call, RouteCounters, Selected, Selection, Taps};

pub use crate::off_path::plane_native_hooks::implicit_strategies;

/// One S8-opened instance; `image` keys the frozen admitted word catalog. The root obtains both
/// identity and words from that instance's admitted descriptor, never from its settings.
pub struct OpenedHook {
    pub port: Arc<dyn HookPort>,
    pub image: Arc<str>,
    pub words: Vec<Box<str>>,
    /// The actual dispatcher call budget, capped by this opened instance's final limits.
    pub timeout: std::time::Duration,
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

/// Frozen attachment inputs shared by pre-open strategy planning and post-open table binding.
/// This pure plan does not authorize dispatch or construct an admitted monetary observation.
pub struct WalkPlan {
    pub(crate) global: Vec<String>,
    pub(crate) section: Vec<String>,
    pub(crate) walks: Vec<WalkBinding>,
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
    pub(crate) scope: SeatScope,
    pub(crate) billing_pool: String,
    pub(crate) tables: WalkTables,
    pub(crate) groups: BTreeMap<String, crate::config::groups::GroupCfg>,
    pub(crate) governance: Arc<GovState>,
    pub(crate) cost: Arc<CostModel>,
    pub(crate) amendments: Arc<NodeAmendments>,
}

/// Owned policy inputs captured before the candidate RootCfg is consumed by App construction.
/// Opened ports and candidate services are supplied only at the later binding step.
pub struct Inputs {
    pub(crate) section: String,
    pub(crate) pool: Option<String>,
    pub(crate) plan: WalkPlan,
    pub(crate) hooks: HookRegistry,
    pub(crate) groups: BTreeMap<String, crate::config::groups::GroupCfg>,
}

impl Bindings {
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

pub(crate) struct Calls<'a> {
    pub(crate) hooks: &'a HookRegistry,
    pub(crate) opened: &'a BTreeMap<String, OpenedHook>,
    /// All admitted images, including unopened ones: required to detect ambiguous words.
    pub(crate) words: &'a BTreeMap<String, Vec<Box<str>>>,
}

pub(crate) struct Bound {
    pub(crate) call: Arc<Call>,
    pub(crate) priority: u16,
    pub(crate) groups: Vec<String>,
    pub(crate) fallback_groups: Vec<Vec<String>>,
}

impl Bound {
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
pub(crate) struct Attached {
    pub(crate) rewrites: Vec<Bound>,
    pub(crate) gates: Vec<Bound>,
    pub(crate) taps: Vec<(HookStage, Bound)>,
}

/// Pure immutable attachment tables; this is not an expanded runtime Binder constructor.
pub struct WalkTables {
    pub(crate) global: Attached,
    pub(crate) section: Attached,
    pub(crate) walks: BTreeMap<String, BTreeMap<String, PoolTable>>,
    /// Whether any attachment of the tables is active (resp. enforcing), decided when they froze.
    pub(crate) active: bool,
    pub(crate) enforcing: bool,
}

pub(crate) struct PoolTable {
    pub(crate) attached: Attached,
    pub(crate) policy: Option<Bound>,
    /// Bound for a configured pool; a direct model has none.
    pub(crate) counters: Option<Arc<RouteCounters>>,
}

struct Chosen {
    rewrites: Vec<Arc<Call>>,
    gates: Vec<Arc<Call>>,
    policy: Option<Arc<Call>>,
    taps: Taps,
    counters: Option<Arc<RouteCounters>>,
}

impl WalkTables {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn enforcing(&self) -> bool {
        self.enforcing
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

#[cfg(test)]
#[path = "native_hook_bindings/tests/construction.rs"]
mod tests;
