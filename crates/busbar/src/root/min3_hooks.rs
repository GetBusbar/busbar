// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native hook inputs are opened in the typed plan and frozen before a plane driver is shared.
use super::*;
use busbar_kernel::plane_driver::native_hook_bindings::{Inputs, OpenedHook};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
#[path = "tests/min3_hook_plan.rs"]
mod tests;

/// Configuration captured before App construction consumes the candidate RootCfg.
pub(crate) struct Plan {
    inputs: BTreeMap<String, Inputs>,
}

impl Plan {
    pub(crate) fn capture(cfg: &RootCfg, instances: &[Configured]) -> Result<Self, String> {
        let mut inputs = BTreeMap::new();
        for instance in instances.iter().filter(|one| one.kind == KindCode::Plane) {
            let name = &instance.name;
            if inputs.contains_key(name) {
                return Err(format!("native hook plan repeats plane `{name}`"));
            }
            inputs.insert(
                name.clone(),
                Inputs::capture(cfg, name.clone(), Some(name.clone()))?,
            );
        }
        // A pool attachment cannot disappear because no native seat walks that pool.
        for (name, pool) in &cfg.pools {
            if (!pool.gates.is_empty() || pool.policy.native_name().is_some())
                && !inputs.contains_key(name)
            {
                return Err(format!(
                    "native hook pool `{name}` has no configured plane walk"
                ));
            }
        }
        Ok(Self { inputs })
    }

    fn check_instances(&self, instances: &[Configured]) -> Result<(), String> {
        let mut planes = BTreeSet::new();
        for instance in instances.iter().filter(|one| one.kind == KindCode::Plane) {
            if !planes.insert(instance.name.as_str()) {
                return Err(format!(
                    "native hook plan repeats plane `{}`",
                    instance.name
                ));
            }
        }
        if planes.len() != self.inputs.len()
            || !self
                .inputs
                .keys()
                .all(|name| planes.contains(name.as_str()))
        {
            return Err("native hook plan differs from the candidate plane instances".into());
        }
        Ok(())
    }
}

pub(crate) struct Environment {
    plan: Plan,
    governance: Arc<busbar_kernel::governance::GovState>,
    cost: Arc<busbar_kernel::cost::CostModel>,
    amendments: Arc<busbar_kernel::audit::amend::NodeAmendments>,
    call_budget: Duration,
}

impl Environment {
    pub(crate) fn new(plan: Plan, app: &busbar_kernel::state::App) -> Result<Self, String> {
        Ok(Self {
            plan,
            governance: app
                .governance
                .clone()
                .ok_or("native hooks need the admitted governance owner")?,
            cost: Arc::clone(&app.cost),
            amendments: Arc::clone(&app.amendments),
            call_budget: crate::root::min3_boot::DEFAULT_CALL_BUDGET,
        })
    }

    pub(super) fn bind(
        &self,
        registry: &MinRegistry,
        instance: &str,
        driver: PortDriver,
        opened: &BTreeMap<String, Opened>,
    ) -> Result<PortDriver, String> {
        let inputs = self.plan.inputs.get(instance).ok_or_else(|| {
            format!("native plane `{instance}` has no captured candidate hook plan")
        })?;
        let ports = opened
            .iter()
            .map(|(name, hook)| {
                let timeout = if hook.limits.timeout_ms == 0 {
                    self.call_budget
                } else {
                    self.call_budget
                        .min(Duration::from_millis(u64::from(hook.limits.timeout_ms)))
                };
                (
                    name.clone(),
                    OpenedHook {
                        port: Arc::clone(&hook.port),
                        image: Arc::clone(&hook.who.plugin),
                        words: hook
                            .described
                            .paths(busbar_plugin_abi::kinds::hook::hook::tag::D_WORD)
                            .map(Box::from)
                            .collect(),
                        timeout,
                    },
                )
            })
            .collect();
        let words = registry
            .hook_words()
            .into_iter()
            .map(|(image, words)| (image.to_owned(), words.into_iter().map(Box::from).collect()))
            .collect();
        let routes = driver
            .routes()
            .data
            .iter()
            .chain(driver.routes().upgrade.iter())
            .chain(driver.routes().line.iter())
            .chain(driver.routes().recovery.iter())
            .map(|route| route.route)
            .collect();
        let bindings = inputs.bind(
            routes,
            &ports,
            &words,
            Arc::clone(&self.governance),
            Arc::clone(&self.cost),
            Arc::clone(&self.amendments),
        )?;
        Ok(if bindings.has_hooks() {
            driver.with_hooks(Arc::new(bindings))
        } else {
            driver
        })
    }

    pub(super) fn check_pools(&self, instances: &[Configured]) -> Result<(), String> {
        self.plan.check_instances(instances)
    }
}

#[derive(Clone)]
pub(crate) struct Opened {
    pub(crate) who: Namespace,
    pub(crate) port: Arc<dyn busbar_ports::hook::HookPort>,
    pub(crate) described: busbar_plugin_loader::instance::Described,
    pub(crate) limits: busbar_plugin_abi::host_side::caller::InstanceLimits,
}

pub(super) fn configured(cfg: &RootCfg) -> Result<Vec<Configured>, String> {
    let seal = busbar_kernel::seal::lend();
    let mut hooks = cfg.hooks.iter().collect::<Vec<_>>();
    hooks.sort_by_key(|(name, _)| *name);
    hooks
        .into_iter()
        .map(|(name, hook)| {
            Ok(Configured {
                kind: KindCode::Hook,
                identity: hook.plugin.clone(),
                name: name.clone(),
                config: hook
                    .settings
                    .encode()
                    .map_err(|why| format!("hooks.{name}: {why}"))?
                    .into_exposed(&seal),
                limits: busbar_kernel::appbuild::instance_limits(cfg, "hooks", name),
            })
        })
        .collect()
}

pub(super) async fn open(
    built: &Built,
    prepared: PreparedInstance,
    prefix: Arc<BootSecrets>,
    records: Records,
    directory: Directory,
) -> Result<Opened, OpenError> {
    let described = built
        .registry
        .described(prepared.identity())
        .ok_or_else(|| OpenError::Unknown("reserved hook lost its admitted descriptor".into()))?;
    let who = Namespace {
        plugin: Arc::from(prepared.identity()),
        name: Arc::from(prepared.name()),
        instance: prepared.id(),
        slot: prepared.slot(),
    };
    let refs = prefix.refs();
    let needs = built.needs_for(prefix, records, directory);
    let (port, limits) = built
        .registry
        .open_hook_reserved_with_limits(prepared, &needs, &refs)
        .await?;
    Ok(Opened {
        who,
        port,
        described,
        limits,
    })
}
