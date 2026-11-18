// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The model-serving egress as one configuration resolves it: its pools and bounds, its probe
//! roster, and the walk composed over them, built once per configuration.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::dest::DestinationId;
use busbar_kernel_egress::ports::Breaker;
use busbar_kernel_egress::{Failover, Member, OnExhausted, Pool};
use foldhash::{HashMap, HashSet};

use crate::root::model_egress::{
    CellPlan, ModelLane, ModelPool, ModelPools, ModelServing, ModelShown, ModelSignals,
    ModelTelemetry, WalkCells,
};

/// The member facts by model, in the map type the kernel's far end takes them as.
pub(crate) type MemberFactsByModel =
    foldhash::HashMap<String, busbar_kernel::plane_driver::MemberFacts>;

impl ModelPools {
    #[must_use]
    pub(crate) fn of(cfg: &busbar_kernel::config::RootCfg) -> Self {
        use busbar_kernel::config::pools::OnExhaustedCfg;
        let mut lanes: BTreeMap<String, ModelLane> = cfg
            .models
            .iter()
            .map(|(name, m)| {
                (
                    name.clone(),
                    ModelLane {
                        max_concurrent: m.max_concurrent,
                        attempt_timeout_ms: m.attempt_timeout_ms,
                        context_max: None,
                    },
                )
            })
            .collect();
        let mut pools = BTreeMap::new();
        for (name, pool) in &cfg.pools {
            for member in &pool.members {
                if let (Some(lane), Some(c)) = (lanes.get_mut(&member.model), member.context_max) {
                    lane.context_max.get_or_insert(c);
                }
            }
            let failover = pool.failover.as_ref().map_or(
                Failover {
                    timeout_secs: busbar_kernel::config::DEFAULT_FAILOVER_DEADLINE_SECS,
                    max_hops: busbar_kernel::config::DEFAULT_FAILOVER_CAP,
                    exclusions: Vec::new(),
                },
                |f| Failover {
                    timeout_secs: f.timeout_secs,
                    max_hops: f.max_hops,
                    exclusions: f.exclusions.clone().unwrap_or_default(),
                },
            );
            let on_exhausted = match &pool.on_exhausted {
                None | Some(OnExhaustedCfg::Reject) => OnExhausted::Status503,
                Some(OnExhaustedCfg::LeastBad) => OnExhausted::LeastBad,
                Some(OnExhaustedCfg::FallbackPool(p)) => OnExhausted::FallbackPool(p.clone()),
                Some(OnExhaustedCfg::Queue { max_ms }) => OnExhausted::Queue { max_ms: *max_ms },
            };
            pools.insert(
                name.clone(),
                ModelPool {
                    members: pool
                        .members
                        .iter()
                        .map(|m| (m.model.clone(), m.weight, m.attempt_timeout_ms))
                        .collect(),
                    failover,
                    on_exhausted,
                    passthrough: pool
                        .upstream_credentials
                        .unwrap_or(cfg.upstream_credentials)
                        == busbar_contract::config::UpstreamCreds::Passthrough,
                },
            );
        }
        let mut records: HashMap<Arc<str>, busbar_kernel::store::BreakerCfg> = cfg
            .pools
            .iter()
            .map(|(name, pool)| {
                (
                    Arc::from(name.as_str()),
                    pool.breaker
                        .as_ref()
                        .map(busbar_kernel::store::breaker_cfg_to_runtime)
                        .unwrap_or_default(),
                )
            })
            .collect();
        records.insert(Arc::from(""), busbar_kernel::store::BreakerCfg::default());
        let probes = cfg
            .models
            .iter()
            .filter_map(|(name, m)| {
                let provider = cfg.providers.get(&m.provider)?;

                if provider.api_key.is_none() {
                    return None;
                }
                let health = provider.health.as_ref()?;
                Some((
                    name.clone(),
                    busbar_kernel::probe::ProbeCfg::resolve(
                        match health.mode {
                            busbar_kernel::config::HealthMode::None => {
                                busbar_kernel::plane_driver::route_input::HealthModeInput::None
                            }
                            busbar_kernel::config::HealthMode::Dead => {
                                busbar_kernel::plane_driver::route_input::HealthModeInput::Dead
                            }
                            busbar_kernel::config::HealthMode::Active => {
                                busbar_kernel::plane_driver::route_input::HealthModeInput::Active
                            }
                        },
                        health.interval_secs,
                        health.timeout_secs,
                        cfg.limits.default_probe_interval_secs,
                        cfg.limits.default_probe_timeout_secs,
                    ),
                ))
            })
            .collect();
        let meta: BTreeMap<_, _> = cfg
            .pools
            .iter()
            .map(|(name, pool)| {
                let members = pool
                    .members
                    .iter()
                    .map(|m| {
                        (
                            m.model.clone(),
                            busbar_kernel::plane_driver::MemberFacts {
                                model: m.model.clone(),
                                tags: m.tags.clone(),
                                tier: m.tier.clone(),
                                cost_per_mtok: cfg
                                    .rate_card
                                    .as_ref()
                                    .and_then(|card| card.get(&m.model))
                                    .map(busbar_kernel::config::rate_entry_per_mtok),
                            },
                        )
                    })
                    .collect();
                (name.clone(), Arc::new(members))
            })
            .collect();
        ModelPools {
            meta: Arc::new(meta),
            pools,
            lanes,
            passthrough: cfg.upstream_credentials
                == busbar_contract::config::UpstreamCreds::Passthrough,
            records: Arc::new(records),
            probes,
        }
    }
}

impl ModelServing {
    #[must_use]
    pub(crate) fn probe_members(
        &self,
    ) -> (
        usize,
        Vec<(DestinationId, busbar_kernel::probe::ProbeMember)>,
    ) {
        let mut members: Vec<(DestinationId, busbar_kernel::probe::ProbeMember)> = self
            .lanes
            .iter()
            .filter_map(|(model, lane)| {
                let cfg = *self.pools.probes.get(model)?;
                Some((
                    DestinationId::new(*lane as u64),
                    busbar_kernel::probe::ProbeMember {
                        index: *lane,
                        name: model.clone(),
                        cfg,
                    },
                ))
            })
            .collect();
        members.sort_by_key(|(_, m)| m.index);
        (self.lanes.values().max().map_or(0, |m| m + 1), members)
    }
}

pub fn compose(
    facts: &crate::root::door_steps::DoorFacts,
    serving: &ModelServing,
    caller: busbar_contract::conn::InstanceId,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    clock: busbar_ports::clock::HostClock,
    stream_ceiling_secs: u64,
) -> Result<(busbar_kernel::plane_driver::Egress, ModelShown), String> {
    let plan = &serving.pools;
    let mut sealed = foldhash::HashMap::default();
    let mut names = Vec::new();
    let mut limits = Vec::new();
    let mut member_of = |model: &str,
                         weight: u32,
                         attempt: Option<u64>,
                         passthrough: bool|
     -> Result<Member, String> {
        let lane = *serving
            .lanes
            .get(model)
            .ok_or_else(|| format!("model '{model}' has no lane in this generation"))?;
        let destination = DestinationId::new(lane as u64);
        let route = routes
            .get(model)
            .ok_or_else(|| format!("model '{model}' has no sealed route"))?;
        let own = plan.lanes.get(model).cloned().unwrap_or_default();
        if let std::collections::hash_map::Entry::Vacant(slot) = sealed.entry(destination) {
            let mut route = route.clone();
            route.keep = facts
                .keeps
                .get(route.need.0 as usize)
                .cloned()
                .unwrap_or_default();
            slot.insert(route);
            names.push((destination, model.to_string()));
            if let Some(n) = own.max_concurrent {
                limits.push((destination, n));
            }
        }
        let mut member = Member::new(destination, model, weight);
        member.attempt_timeout_ms = attempt.or(own.attempt_timeout_ms);
        member.context_max = own.context_max.map(|c| c as u64);
        member.passthrough = passthrough;
        Ok(member)
    };
    let mut built: foldhash::HashMap<String, Pool> = foldhash::HashMap::default();
    for (name, pool) in &plan.pools {
        let members = pool
            .members
            .iter()
            .map(|(model, weight, attempt)| {
                member_of(model, *weight, *attempt, pool.passthrough)
                    .map_err(|e| format!("pool '{name}': {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut p = Pool::new(name.clone(), members);
        p.set_failover(pool.failover.clone());
        p.on_exhausted = pool.on_exhausted.clone();
        built.insert(name.clone(), p);
    }
    let mut direct = HashSet::default();
    for model in routes.keys() {
        if built.contains_key(model) || !serving.lanes.contains_key(model) {
            continue;
        }
        let member = member_of(model, 1, None, plan.passthrough)?;
        let mut p = Pool::new(model.clone(), vec![member]);
        p.set_failover(Failover {
            timeout_secs: busbar_kernel::config::DEFAULT_FAILOVER_DEADLINE_SECS,
            max_hops: busbar_kernel::config::DEFAULT_FAILOVER_CAP,
            exclusions: Vec::new(),
        });
        built.insert(model.clone(), p);
        direct.insert(model.clone());
    }
    let permits = Arc::new(crate::root::egress_ports::MemberPermits::new(limits));
    let stable_names: Arc<HashMap<DestinationId, String>> =
        Arc::new(names.iter().cloned().collect());
    let shown = ModelShown {
        described: Arc::clone(&plan.meta),
        signals: Arc::new(ModelSignals {
            app: serving.app.clone(),
            names: Arc::clone(&stable_names),
            permits: Arc::clone(&permits),
        }),
    };
    let cells = Arc::new(CellPlan {
        records: Arc::clone(&plan.records),
        direct,
        names: Arc::clone(&stable_names),
    });
    let app = serving.app.clone();
    let breaker: busbar_kernel::plane_driver::BreakerSource =
        Arc::new(move || -> Arc<dyn Breaker> {
            Arc::new(WalkCells::over(app.clone(), Arc::clone(&cells)))
        });
    Ok((
        busbar_kernel::plane_driver::Egress {
            caller,
            conns,
            breaker,
            capacity: permits,
            clock,
            journal,
            telemetry: Arc::new(ModelTelemetry {
                app: serving.app.clone(),
                names: stable_names,
                queued: crate::root::egress_ports::WalkTelemetry::new(names),
            }),
            pools: built,
            routes: sealed,
            stream_ceiling_secs,
            stated_ceiling_secs: facts.stream_ceiling_secs,
            error_body_max: busbar_kernel::config::limits::installed().map_or(
                busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
                |limits| limits.upstream_error_body_max_bytes,
            ),
        },
        shown,
    ))
}
