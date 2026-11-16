// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel directory behind DIRECTORY Needs, and the CA-5 hold index (IF §12.29). One [`KernelDirectory`] serves
//! every `auth.<name>.provisioning` instance of a config generation; [`Holds`] is the per-generation CA-5 index
//! built beside it.

mod config;
mod events;
mod holds;
mod ops;
mod store;

use core::future::Future;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;

use arc_swap::ArcSwap;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};
use tokio::sync::Notify;

use crate::config::min3::ProvisioningCfg;
use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::ScopedStore;

pub use config::{check_provisioning, ProvisioningFacts};
pub use events::{DirEvent, DirectoryEvents, LogEvents};
pub use ops::GuardView;

/// K6p (`busbar-kernel/src/directory/`). Passed to `HostNeeds::new` (§13). Round 30: `linked_state` is withdrawn;
/// the hold is `Holds` below.
pub trait PluginDirectory: Send + Sync + 'static {
    /// The whole DIRECTORY Need. Writes a/b, data0 and the 16-byte `DirFacts` into `res` (§10.3 `Needs::directory`).
    /// Err(NeedErr::Denied) = the instance has no `provisioning:` block; Err(Unavailable) = store fault or the
    /// write lost the optimistic race MAX_ATTEMPTS times. Domain outcomes (dir::NOT_FOUND..=GUARD) are Ok.
    fn apply(
        &self,
        who: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send;
}
/// K6p. One write's optimistic attempts before Unavailable (audited `directory_contended`). Not RetryPolicy: a
/// ConditionConflict is not a failure.
pub const MAX_ATTEMPTS: u32 = 4;
/// K6p. Held principals per provisioning instance. A write that would hold more answers dir::TOO_MANY, writes
/// nothing, audits and alerts `provisioning_held_full`.
pub const MAX_HELD: u32 = 262_144;

/// K6p, the CA-5 index. Built per config generation from every `provisioning.link`. K8p resolves `for_inbound`
/// once per generation and keeps the answer beside the inbound auth port; the request path never calls it.
pub struct Holds {
    /// Inbound auth instance id -> the hold sets of the provisioning instances whose `link.auth` names it. Only
    /// instances named in some link.auth have an entry.
    by_inbound: HashMap<u64, Box<[Arc<HoldSet>]>>,
}
impl Holds {
    /// None = no provisioning instance links `inbound`: K8p makes no probe for it at all.
    pub fn for_inbound(&self, inbound: u64) -> Option<&[Arc<HoldSet>]> {
        self.by_inbound.get(&inbound).map(|sets| &**sets)
    }
}
/// One provisioning instance's held principals (the `link.index` values of its INACTIVE subjects).
pub struct HoldSet {
    /// Held principals; 0 = none (the probe's one load).
    len: AtomicU32,
    set: ArcSwap<holds::Held>,
    /// Wakes the refresh task after this replica's own write.
    wake: Notify,
    /// The store generation `set` was read at.
    generation: AtomicU64,
}
impl HoldSet {
    /// true = `principal` is held. Sync, no allocation, no lock, no await: one Relaxed load of `len` (0 = false);
    /// otherwise one `ArcSwap::load` (2 RMWs on the caller's own debt slot, §0 I5's fourth exception) and one
    /// foldhash probe of the principal bytes. B-HOLD (§14).
    pub fn holds(&self, principal: &str) -> bool {
        if self.len() == 0 {
            return false;
        }
        self.set.load().contains(principal)
    }
}

/// One provisioning instance as config load resolved it.
pub struct ProvisioningInstance {
    /// The verified plugin stamp name of the instance's image.
    pub plugin: Box<str>,
    /// The operator's instance name (`Caller::name`).
    pub name: Box<str>,
    pub cfg: ProvisioningCfg,
    /// Runtime ids of the inbound auth instances `cfg.link.auth` names, in the same order.
    pub link_auth_ids: Vec<u64>,
}

/// One instance's runtime state.
pub(crate) struct Instance {
    pub(crate) name: Box<str>,
    pub(crate) scope: ScopedStore,
    pub(crate) cfg: ProvisioningCfg,
    /// Some only when the instance has a `link`.
    pub(crate) held: Option<Arc<HoldSet>>,
    /// The guard window an alert was last raised for (once per window).
    pub(crate) tripped: AtomicU64,
}

/// The directory of one config generation.
pub struct KernelDirectory {
    store: Arc<CoreStore>,
    events: Arc<dyn DirectoryEvents>,
    instances: HashMap<Box<str>, Instance>,
}

impl KernelDirectory {
    /// Binds every instance's scope and, for each with a `link`, loads its HoldSet by a full scan before this
    /// generation serves, then starts its refresh task (must run inside a tokio runtime). Err = the instance
    /// whose store could not be read: the generation does not serve.
    pub async fn build(
        store: Arc<CoreStore>,
        events: Arc<dyn DirectoryEvents>,
        specs: Vec<ProvisioningInstance>,
    ) -> Result<(Self, Holds), String> {
        let mut instances = HashMap::new();
        let mut by_inbound: HashMap<u64, Vec<Arc<HoldSet>>> = HashMap::new();
        for spec in specs {
            let scope = store::scope(&store, &spec.plugin, &spec.name).map_err(|_| {
                format!(
                    "auth.{}.provisioning: the directory store is unavailable",
                    spec.name
                )
            })?;
            let held = match &spec.cfg.link {
                None => None,
                Some(link) => {
                    let (held, generation) = holds::load(&scope).await.map_err(|()| {
                        format!(
                            "auth.{}.provisioning: the held set could not be loaded from the store",
                            spec.name
                        )
                    })?;
                    let set = Arc::new(HoldSet::new(held, generation));
                    holds::spawn_refresh(
                        &set,
                        scope.clone(),
                        link.refresh_ms,
                        spec.name.clone(),
                        Arc::clone(&events),
                    );
                    for id in &spec.link_auth_ids {
                        by_inbound.entry(*id).or_default().push(Arc::clone(&set));
                    }
                    Some(set)
                }
            };
            instances.insert(
                spec.name.clone(),
                Instance {
                    name: spec.name,
                    scope,
                    cfg: spec.cfg,
                    held,
                    tripped: AtomicU64::new(0),
                },
            );
        }
        let by_inbound = by_inbound
            .into_iter()
            .map(|(id, sets)| (id, sets.into_boxed_slice()))
            .collect();
        Ok((
            Self {
                store,
                events,
                instances,
            },
            Holds { by_inbound },
        ))
    }

    fn cx<'a>(&'a self, inst: &'a Instance) -> ops::Cx<'a> {
        ops::Cx {
            store: &self.store,
            inst,
            now: crate::store::vocab::now(),
            events: &*self.events,
        }
    }

    fn instance(&self, name: &str) -> Result<&Instance, NeedErr> {
        self.instances.get(name).ok_or(NeedErr::Denied)
    }

    /// The mass-deprovision guard of `instance` as the admin API shows it. Err(Denied) = no such instance.
    pub async fn guard(&self, instance: &str) -> Result<GuardView, NeedErr> {
        let inst = self.instance(instance)?;
        ops::guard_view(&self.cx(inst)).await
    }

    /// Release the guard of `instance` for `for_s` seconds (60..=86,400), audited with the admin principal.
    pub async fn release_guard(
        &self,
        instance: &str,
        for_s: u64,
        admin: &str,
    ) -> Result<GuardView, NeedErr> {
        let inst = self.instance(instance)?;
        ops::release(&self.cx(inst), for_s, admin).await
    }
}

impl PluginDirectory for KernelDirectory {
    async fn apply(
        &self,
        who: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let inst = self.instance(who.name)?;
        ops::run(&self.cx(inst), n, res).await
    }
}

#[cfg(test)]
mod tests;
