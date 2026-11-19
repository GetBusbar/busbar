// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native hook assembly over already-opened ports and admitted descriptors. Nothing in this
//! snapshot owns an App, serving generation, loader, or mutable publication slot.

//! The tables are resolved and frozen off the request path (`off_path::plane_native_hooks`); a
//! request only selects from them ([`Bindings::select`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_ports::hook::HookPort;

use crate::audit::amend::NodeAmendments;
use crate::config::hooks::HookRegistry;
use crate::config::HookStage;
use crate::cost::CostModel;
use crate::governance::GovState;

use super::hooks::{CallerKey, HookRead};
use super::port_hooks::{Call, RouteCounters, Selected, Selection, Taps};

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
/// Complete per-seat policy, frozen before the driver or any tick worker is published.
pub struct Bindings {
    pub(crate) scope: SeatScope,
    pub(crate) billing_pool: String,
    pub(crate) tables: WalkTables,
    /// What every caller group selects in every scope, decided when the tables froze.
    pub(crate) selections: Selections,
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

/// What a request asks of its seat's frozen hook policy: whether a route has hooks, whether they
/// can enforce, and the selection for one request. Built by S9 from admitted metadata and the
/// exact S8 hook ports before seats are published; it retains concrete governance readers, never
/// App or a generation.
impl Bindings {
    pub fn has_hooks(&self) -> bool {
        self.tables.active()
    }

    /// Includes possible pool/container attachments, not merely the currently known section hooks.
    pub fn active(&self, route: u32) -> bool {
        self.scope.routes.contains(&route) && self.tables.active()
    }

    /// True when a gate, rewrite or routing policy can enforce this route.
    pub fn enforcing(&self, route: u32) -> bool {
        self.scope.routes.contains(&route) && self.tables.enforcing()
    }

    pub fn select(&self, input: &Selection<'_>) -> Result<Selected, &'static str> {
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
            .selections
            .scope(input.pool, input.container)?
            .of(group);
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
            rewrites: Arc::clone(&selected.rewrites),
            gates: Arc::clone(&selected.gates),
            policy: selected.policy.clone(),
            taps: selected.taps.clone(),
            key: key.map(|k| CallerKey {
                id: k.id.clone(),
                name: k.name.clone(),
            }),
            budget,
            rate_headroom,
            cost: self.cost.clone(),
            reads,
            counters: selected.counters.clone(),
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

/// One caller group's selection in one scope: the calls it runs, in their frozen order.
pub(crate) struct Chosen {
    pub(crate) rewrites: Arc<[Arc<Call>]>,
    pub(crate) gates: Arc<[Arc<Call>]>,
    pub(crate) policy: Option<Arc<Call>>,
    pub(crate) taps: Taps,
    pub(crate) counters: Option<Arc<RouteCounters>>,
}

/// Every caller group's selection in one scope (`off_path::plane_native_hooks` builds it from the tables and the
/// group tree): no group, each group the tree or a hook attachment names, and any other group (which an
/// attachment with groups never admits).
pub(crate) struct Frozen {
    pub(crate) none: Chosen,
    pub(crate) named: BTreeMap<String, Chosen>,
    pub(crate) other: Chosen,
}

impl Frozen {
    fn of(&self, group: Option<&str>) -> &Chosen {
        match group {
            None => &self.none,
            Some(group) => self.named.get(group).unwrap_or(&self.other),
        }
    }
}

/// The frozen selections of a seat: the unscoped one, and one per configured (pool, container) walk.
pub(crate) struct Selections {
    pub(crate) unscoped: Frozen,
    pub(crate) walks: BTreeMap<String, BTreeMap<String, Frozen>>,
}

impl Selections {
    fn scope(&self, pool: &str, container: &str) -> Result<&Frozen, &'static str> {
        if pool.is_empty() && container.is_empty() {
            return Ok(&self.unscoped);
        }
        self.walks
            .get(pool)
            .and_then(|walks| walks.get(container))
            .ok_or("native hook scope is outside the configured walk")
    }
}

impl WalkTables {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn enforcing(&self) -> bool {
        self.enforcing
    }
}

/// A seat over `routes`, walking `pool`, whose frozen tables are active and enforcing and where
/// every caller, unscoped and in `pool`'s walk, selects `chosen`'s calls: what a driver test needs
/// without a RootCfg and opened ports. [`Bindings::select`] still runs as in production over
/// these tables.
#[cfg(test)]
impl Bindings {
    pub(crate) fn selecting(
        routes: Vec<u32>,
        pool: &str,
        chosen: &Selected,
        governance: Arc<GovState>,
    ) -> Self {
        let frozen = || Chosen {
            rewrites: Arc::clone(&chosen.rewrites),
            gates: Arc::clone(&chosen.gates),
            policy: chosen.policy.clone(),
            taps: chosen.taps.clone(),
            counters: chosen.counters.clone(),
        };
        Self {
            scope: SeatScope {
                section: "test".into(),
                routes,
                pool: Some(pool.into()),
            },
            billing_pool: String::new(),
            tables: WalkTables {
                global: Attached::default(),
                section: Attached::default(),
                walks: BTreeMap::new(),
                active: true,
                enforcing: true,
            },
            selections: Selections {
                unscoped: Frozen {
                    none: frozen(),
                    named: BTreeMap::new(),
                    other: frozen(),
                },
                walks: BTreeMap::from([(
                    pool.to_string(),
                    BTreeMap::from([(
                        String::new(),
                        Frozen {
                            none: frozen(),
                            named: BTreeMap::new(),
                            other: frozen(),
                        },
                    )]),
                )]),
            },
            governance,
            cost: Arc::clone(&chosen.cost),
            amendments: Arc::new(NodeAmendments::new()),
        }
    }
}

#[cfg(test)]
#[path = "native_hook_bindings/tests/construction.rs"]
mod tests;
