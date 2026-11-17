// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native hook inputs are opened in the typed plan and frozen before a plane driver is shared.
use super::*;
use busbar_kernel::plane_driver::native_hook_bindings::{Bindings, OpenedHook, SeatScope};
use std::collections::BTreeMap;

pub(crate) struct Environment<'a> {
    cfg: &'a RootCfg,
    governance: Arc<busbar_kernel::governance::GovState>,
    cost: Arc<busbar_kernel::cost::CostModel>,
    amendments: Arc<busbar_kernel::audit::amend::NodeAmendments>,
    call_budget: Duration,
}

impl<'a> Environment<'a> {
    pub(crate) fn new(cfg: &'a RootCfg, app: &busbar_kernel::state::App) -> Result<Self, String> {
        Ok(Self {
            cfg,
            governance: app
                .governance
                .clone()
                .ok_or("native hooks need the admitted governance owner")?,
            cost: Arc::clone(&app.cost),
            amendments: Arc::clone(&app.amendments),
            call_budget: crate::root::dispatch::dispatcher().budgets().call,
        })
    }

    pub(super) fn bind(
        &self,
        registry: &MinRegistry,
        instance: &str,
        driver: PortDriver,
        opened: &BTreeMap<String, Opened>,
    ) -> Result<PortDriver, String> {
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
        let scope = SeatScope {
            section: instance.to_owned(),
            pool: Some(instance.to_owned()),
            routes: driver
                .routes()
                .data
                .iter()
                .map(|route| route.route)
                .collect(),
        };
        let bindings = Bindings::build(
            self.cfg,
            scope,
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

    /// A pool attachment cannot disappear because no native seat walks that configured pool.
    pub(super) fn check_pools(&self, instances: &[Configured]) -> Result<(), String> {
        for (name, pool) in &self.cfg.pools {
            if (!pool.gates.is_empty() || pool.policy.native_name().is_some())
                && !instances
                    .iter()
                    .any(|one| one.kind == KindCode::Plane && one.name == *name)
            {
                return Err(format!(
                    "native hook pool `{name}` has no configured plane walk"
                ));
            }
        }
        Ok(())
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
