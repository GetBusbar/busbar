// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS OF THE PLANE SERVING THE `pools` MAP, sealed with the previous release's pool
//! semantics (BUSBAR-1.6.0.md Part 3 §12 "The route pump": the route step is the kernel's existing
//! egress walk; Part 1: customer-visible behaviour is 1.5.5's).
//!
//! The generic door egress ([`crate::root::door_steps::compose_egress`]) seals every member at
//! weight 1 under the default breaker ladder on a breaker of its own. The `pools:` grammar is the
//! kernel's and says more, and 1.5.5 honoured all of it: each member's weight and attempt timeout,
//! each model's concurrency cap and context window, each pool's failover budget, hop cap and
//! exclusions, its exhaustion terminal and its breaker ladder. And the breaker cells a member trips
//! are the kernel's own lane cells (`AppHandle::store`), keyed by the model's lane index, so the
//! admission the kernel reads, the `busbar_lane_*` gauges a scrape renders and the admin health views
//! all read the trip a door-served attempt recorded, as they read the previous release's. Every
//! outcome is recorded through the lane store's own record calls, the ones the previous release's
//! attempt made (success, transient, rate limit, client fault, hard-down), so the lane's lifetime
//! counters `/stats` renders count it too. A route that names a model directly walks it alone under
//! the model's name (its metric label) on the lane-default cell (`""`), as 1.5.5 attributed a
//! model-routed fault.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use busbar_contract::caps::{Pass, Route};
use busbar_contract::dest::DestinationId;
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, Outcome, Unavailable, UpstreamStatus,
};
use busbar_kernel_egress::{Failover, Member, OnExhausted, Pool};

use crate::root::adapters::{BreakerAdapter, BreakerPolicy};

/// The kernel's App, as the live configuration answers it (a config apply rebuilds it, its lane
/// store and its telemetry bank with it).
pub type AppSource = Arc<dyn Fn() -> Arc<busbar_kernel::state::App> + Send + Sync>;

/// One configured pool: its members (model, weight, attempt timeout), failover bounds and
/// exhaustion terminal.
#[derive(Debug, Clone)]
struct ModelPool {
    members: Vec<(String, u32, Option<u64>)>,
    failover: Failover,
    on_exhausted: OnExhausted,
    /// Its members are reached with the caller's own credential (the pool's
    /// `upstream_credentials:`, else the all-pools default, is `passthrough`).
    passthrough: bool,
}

/// One model's own bounds: its concurrency cap, its attempt timeout and its context window.
#[derive(Debug, Clone, Default)]
struct ModelLane {
    max_concurrent: Option<usize>,
    attempt_timeout_ms: Option<u64>,
    context_max: Option<usize>,
}

/// THE MODEL-SERVING POOLS as the configuration resolved them, captured before the configuration
/// is consumed: every pool and model bound the walk honours, and the breaker ladder of each pool.
#[derive(Debug, Clone, Default)]
pub struct ModelPools {
    pools: BTreeMap<String, ModelPool>,
    lanes: BTreeMap<String, ModelLane>,
    breaker: BreakerPolicy,
    /// The all-pools `upstream_credentials:` default is `passthrough`: a route naming a model
    /// directly reaches it with the caller's own credential.
    passthrough: bool,
    /// Each pool's ladder as the lane store's record calls take it (the previous release's
    /// `resolve_breaker_cfg`: the pool's own, else the default); `""` = the lane-default cell's.
    records: HashMap<String, busbar_kernel::store::BreakerCfg>,
    /// Each model's active health probing (K7): its provider's `health:` over the process-wide
    /// defaults, as 1.5.5's prober resolved it per lane.
    probes: BTreeMap<String, busbar_kernel::probe::ProbeCfg>,
}

impl ModelPools {
    /// The pools and models `cfg` resolved.
    #[must_use]
    pub fn of(cfg: &busbar_kernel::config::RootCfg) -> Self {
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
        let mut records: HashMap<String, busbar_kernel::store::BreakerCfg> = cfg
            .pools
            .iter()
            .map(|(name, pool)| {
                (
                    name.clone(),
                    pool.breaker
                        .as_ref()
                        .map(busbar_kernel::store::breaker_cfg_to_runtime)
                        .unwrap_or_default(),
                )
            })
            .collect();
        records.insert(String::new(), busbar_kernel::store::BreakerCfg::default());
        let probes = cfg
            .models
            .iter()
            .filter_map(|(name, m)| {
                let health = cfg.providers.get(&m.provider)?.health.as_ref()?;
                Some((
                    name.clone(),
                    busbar_kernel::probe::ProbeCfg::resolve(
                        match health.mode {
                            busbar_kernel::config::HealthMode::None => {
                                busbar_kernel::plane_host::HealthModeInput::None
                            }
                            busbar_kernel::config::HealthMode::Dead => {
                                busbar_kernel::plane_host::HealthModeInput::Dead
                            }
                            busbar_kernel::config::HealthMode::Active => {
                                busbar_kernel::plane_host::HealthModeInput::Active
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
        ModelPools {
            pools,
            lanes,
            breaker: BreakerPolicy::from_pools(&cfg.pools),
            passthrough: cfg.upstream_credentials
                == busbar_contract::config::UpstreamCreds::Passthrough,
            records,
            probes,
        }
    }
}

impl ModelServing {
    /// THE MEMBERS THE HEALTH-PROBE SERVICE SCHEDULES (K7), in lane order: each model with a
    /// probing mode, at its lane's index and destination, under its resolved settings.
    #[must_use]
    pub fn probe_members(
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

/// WHAT THE MODEL-SERVING EGRESS IS SEALED OVER beside the plane's member routes: the pools, the
/// lane index of each model in the generation's lane table (the kernel's breaker cells are keyed by
/// it), and the breaker unit those cells live in, as the live configuration answers it.
pub struct ModelServing {
    /// The pools and models.
    pub pools: ModelPools,
    /// Each model's lane index.
    pub lanes: HashMap<String, usize>,
    /// The kernel's App, read on every call: its lane store and its telemetry bank.
    pub app: AppSource,
}

impl std::fmt::Debug for ModelServing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelServing")
            .field("pools", &self.pools)
            .field("lanes", &self.lanes)
            .finish_non_exhaustive()
    }
}

/// The kernel's breaker port over its lane store: a model-named direct route is mapped onto the
/// lane-default cell, and every outcome is recorded through the store's own record calls.
struct DirectCells {
    inner: BreakerAdapter,
    app: AppSource,
    records: HashMap<String, busbar_kernel::store::BreakerCfg>,
    direct: HashSet<String>,
}

/// The lane a destination of this egress names (its destination is the model's lane index).
fn lane_of(destination: DestinationId) -> usize {
    usize::try_from(destination.get()).unwrap_or(usize::MAX)
}

impl DirectCells {
    fn cell<'p>(&self, pool: &'p str) -> &'p str {
        if self.direct.contains(pool) {
            ""
        } else {
            pool
        }
    }
}

impl Breaker for DirectCells {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        self.inner.try_admit(self.cell(pool), destination, now)
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        self.inner.ready(self.cell(pool), destination, now, token)
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        self.inner.admissible(destination)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        self.inner
            .cooldown_remaining(self.cell(pool), destination, now, token)
    }

    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified {
        self.inner.classify(destination, status)
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        _now: u64,
        _token: &Pass<Route>,
    ) -> bool {
        let cell = self.cell(pool);
        let Some(cfg) = self.records.get(cell) else {
            return false;
        };
        let (store, lane) = (Arc::clone(&(self.app)().store), lane_of(destination));
        match outcome {
            Outcome::Success => {
                store.record_success_in(cell, lane);
                false
            }
            Outcome::Transient { retry_after } => {
                store.record_transient_in(cell, lane, "transient", cfg, retry_after)
            }
            Outcome::HardDown => store.record_hard_down_all_cells(lane, "hard_down"),
            Outcome::RecordNothing => false,
        }
    }

    fn judge(
        &self,
        pool: &str,
        destination: DestinationId,
        status: UpstreamStatus,
        now: u64,
        token: &Pass<Route>,
    ) -> (Classified, bool) {
        let classified = self.classify(destination, status);
        let code = status
            .code
            .filter(|c| c.namespace == busbar_contract::transport::registry::status_ns::HTTP)
            .map(|c| c.code);
        let cell = self.cell(pool);
        let lane = lane_of(destination);
        let tripped = match (classified.outcome, code) {
            // The previous release's rate-limit record: its own ladder step, the far end's wait
            // honoured.
            (Outcome::Transient { retry_after }, Some(429)) => match self.records.get(cell) {
                Some(cfg) => {
                    (self.app)()
                        .store
                        .record_rate_limit_in(cell, lane, now, cfg, retry_after)
                }
                None => false,
            },
            // The caller's own fault: counted on the lane, its breaker untouched.
            (Outcome::RecordNothing, Some(400..=499)) => {
                (self.app)().store.record_client_fault(lane);
                false
            }
            (outcome, _) => self.observe(pool, destination, outcome, now, token),
        };
        (classified, tripped)
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        (self.app)()
            .store
            .lane_needs_probe(lane_of(destination), now)
    }

    /// A health probe's answer, recorded as 1.5.5's prober recorded it (`engine/health.rs`): a
    /// success recovers the lane in every cell, then joins every cell's window; a transient failure
    /// joins every cell's window under its own pool's ladder; a hard-down parks the lane in every
    /// cell; a client fault records nothing.
    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, _token: &Pass<Route>) {
        let (app, lane) = ((self.app)(), lane_of(destination));
        let store = &app.store;
        match outcome {
            Outcome::Success => {
                if store.lane_needs_probe(lane, now) {
                    store.recover_lane(lane);
                }
                store.record_probe_success_all_cells(lane);
            }
            Outcome::Transient { retry_after } => {
                let resolve = |pool: &str| self.records.get(pool).cloned().unwrap_or_default();
                store.record_probe_failure_all_cells(lane, "health-probe", &resolve, retry_after);
            }
            Outcome::HardDown => {
                let _ =
                    store.record_hard_down_all_cells(lane, "health-probe hard-down (auth/billing)");
            }
            Outcome::RecordNothing => {}
        }
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.inner
            .release_probe(self.cell(pool), destination, epoch, now);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.inner.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.inner.refund_budget(destination);
    }
}

/// The walk's counters on the kernel's telemetry bank, as the previous release's attempt counted
/// them: each member by its lane index, under the pool label the walk names (a pool, or the model a
/// direct route names); the wait-terminal depth as the root's walk counters keep it.
struct ModelTelemetry {
    app: AppSource,
    queued: crate::root::egress_ports::WalkTelemetry,
}

impl busbar_kernel_egress::ports::Telemetry for ModelTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::upstream_attempt(&(self.app)(), pool, lane_of(destination));
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str) {
        busbar_kernel::telemetry::upstream_failure(
            &(self.app)(),
            pool,
            lane_of(destination),
            disposition,
        );
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        busbar_kernel::telemetry::failover(&(self.app)(), pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::breaker_trip(&(self.app)(), pool, lane_of(destination));
    }

    fn upstream_latency(&self, destination: DestinationId, ms: f64) {
        // The lane's latency signal (the admin pool listing's `latency_ms`, the `fastest` order's
        // input), as 1.5.5's served attempt recorded it.
        (self.app)()
            .store
            .record_latency_in("", lane_of(destination), ms);
    }

    fn queued(&self, pool: &str, delta: i64) {
        busbar_kernel_egress::ports::Telemetry::queued(&self.queued, pool, delta);
        // The scrape's pool-queue gauge reads the depth the kernel's tables report.
        busbar_kernel::plane_host::set_pool_queued_depth(
            pool,
            u64::try_from(self.queued.depth(pool)).unwrap_or(0),
        );
    }
}

/// THE EGRESS OF THE PLANE SERVING THE `pools` MAP (module doc): one member per sealed entry (its
/// destination the model's lane index, its name the model's), a pool per configured pool with its
/// own bounds and terminal, a pool per model a route may name directly, the kernel's breaker cells
/// under each pool's ladder, each model's concurrency cap, the node's clock and counters, and
/// `journal`.
///
/// # Errors
///
/// A configured pool naming a model with no sealed route or no lane: the load is refused, naming
/// both.
#[allow(clippy::too_many_arguments)]
pub fn compose(
    facts: &crate::root::door_steps::DoorFacts,
    serving: &ModelServing,
    caller: busbar_contract::conn::InstanceId,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    stream_ceiling_secs: u64,
) -> Result<busbar_kernel::plane_driver::Egress, String> {
    let plan = &serving.pools;
    let mut sealed = HashMap::new();
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
    let mut built: HashMap<String, Pool> = HashMap::new();
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
        p.failover = pool.failover.clone();
        p.on_exhausted = pool.on_exhausted.clone();
        built.insert(name.clone(), p);
    }
    let mut direct = HashSet::new();
    for model in routes.keys() {
        if built.contains_key(model) || !serving.lanes.contains_key(model) {
            continue;
        }
        let member = member_of(model, 1, None, plan.passthrough)?;
        let mut p = Pool::new(model.clone(), vec![member]);
        p.failover = Failover {
            timeout_secs: busbar_kernel::config::DEFAULT_FAILOVER_DEADLINE_SECS,
            max_hops: busbar_kernel::config::DEFAULT_FAILOVER_CAP,
            exclusions: Vec::new(),
        };
        built.insert(model.clone(), p);
        direct.insert(model.clone());
    }
    let app = Arc::clone(&serving.app);
    let breaker = DirectCells {
        inner: BreakerAdapter::over(
            Arc::new(move || app().store.breaker_unit()),
            plan.breaker.clone(),
        ),
        app: Arc::clone(&serving.app),
        records: plan.records.clone(),
        direct,
    };
    Ok(busbar_kernel::plane_driver::Egress {
        caller,
        conns,
        breaker: Arc::new(breaker),
        capacity: Arc::new(crate::root::egress_ports::MemberPermits::new(limits)),
        clock: Arc::new(crate::root::egress_ports::NodeClock::new()),
        journal,
        telemetry: Arc::new(ModelTelemetry {
            app: Arc::clone(&serving.app),
            queued: crate::root::egress_ports::WalkTelemetry::new(names),
        }),
        floor: busbar_kernel_egress::WeightedFloor::new(),
        pools: built,
        routes: sealed,
        stream_ceiling_secs,
        error_body_max: busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
    })
}
