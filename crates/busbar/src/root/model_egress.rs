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

use crate::root::adapters;

/// The kernel's App, as the live configuration answers it (a config apply rebuilds it, its lane
/// store and its telemetry bank with it): the swap handle once boot has made one, the App the
/// egress was composed with until then.
#[derive(Clone)]
pub struct LiveApp {
    handle: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::AppHandle>>>,
    fallback: Arc<busbar_kernel::state::App>,
}

impl LiveApp {
    /// The live App: `handle`'s once it is set, `fallback` until then.
    #[must_use]
    pub fn new(
        handle: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::AppHandle>>>,
        fallback: Arc<busbar_kernel::state::App>,
    ) -> Self {
        LiveApp { handle, fallback }
    }

    /// One App, never swapped.
    #[must_use]
    pub fn fixed(app: Arc<busbar_kernel::state::App>) -> Self {
        LiveApp::new(Arc::default(), app)
    }

    /// The live App, owned.
    #[must_use]
    pub fn load(&self) -> Arc<busbar_kernel::state::App> {
        self.handle
            .get()
            .map_or_else(|| Arc::clone(&self.fallback), |h| h.load())
    }

    /// Whether `app` is still the live App: a borrow of the handle's pointer, no refcount.
    fn is_current(&self, app: &Arc<busbar_kernel::state::App>) -> bool {
        match self.handle.get() {
            Some(h) => Arc::ptr_eq(&h.snapshot(), app),
            None => Arc::ptr_eq(&self.fallback, app),
        }
    }
}

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
    /// The all-pools `upstream_credentials:` default is `passthrough`: a route naming a model
    /// directly reaches it with the caller's own credential.
    passthrough: bool,
    /// Each pool's ladder as the lane store's record calls take it (the previous release's
    /// `resolve_breaker_cfg`: the pool's own, else the default); `""` = the lane-default cell's.
    records: HashMap<String, busbar_kernel::store::BreakerCfg>,
    /// Each model's active health probing (K7): its provider's `health:` over the process-wide
    /// defaults, as 1.5.5's prober resolved it per lane.
    probes: BTreeMap<String, busbar_kernel::probe::ProbeCfg>,
    /// What each pool's members show the ranking hooks, by pool then model: the member's tier and
    /// tags, and its model's cost per million tokens off the rate card (1.5.5's pool member meta).
    meta: BTreeMap<String, Arc<HashMap<String, busbar_kernel::plane_driver::MemberFacts>>>,
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
                let provider = cfg.providers.get(&m.provider)?;
                // A keyless lane (`api_key: none`) is not probed: it holds no credential, as
                // 1.5.5's prober skipped a lane with no key ("no key, no probe").
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
        let meta = cfg
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
            meta,
            pools,
            lanes,
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
    /// The kernel's App: its lane store and its telemetry bank.
    pub app: LiveApp,
}

impl std::fmt::Debug for ModelServing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelServing")
            .field("pools", &self.pools)
            .field("lanes", &self.lanes)
            .finish_non_exhaustive()
    }
}

/// The number of latency samples a lane's p95 reservoir holds (1.5.5's ring).
const LATENCY_RESERVOIR_LEN: usize = 128;

/// ONE LANE'S P95 LATENCY RESERVOIR (1.5.5's `LatencyReservoir`, moved verbatim): a ring of the
/// last [`LATENCY_RESERVOIR_LEN`] samples in microseconds, written lock-free. The p95 is computed
/// once per new sample, not once per read: the ranking hooks read it per member per request.
#[derive(Debug)]
pub struct LatencyReservoir {
    cursor: std::sync::atomic::AtomicUsize,
    samples: [std::sync::atomic::AtomicU32; LATENCY_RESERVOIR_LEN],
    /// Bumped after each sample lands: the generation a cached p95 is tagged with.
    written: std::sync::atomic::AtomicU32,
    /// The last p95 computed: its `written` generation in the high half, the value + 1 in the low
    /// half (`0` = no sample held). Generation 0 holds no sample, so the initial `0` is exact.
    p95: std::sync::atomic::AtomicU64,
}

impl Default for LatencyReservoir {
    fn default() -> Self {
        Self {
            cursor: std::sync::atomic::AtomicUsize::new(0),
            samples: std::array::from_fn(|_| std::sync::atomic::AtomicU32::new(0)),
            written: std::sync::atomic::AtomicU32::new(0),
            p95: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl LatencyReservoir {
    /// Record one sample, in milliseconds. A non-finite or non-positive sample is ignored.
    pub fn record(&self, latency_ms: f64) {
        use std::sync::atomic::Ordering;
        if !latency_ms.is_finite() || latency_ms <= 0.0 {
            return;
        }
        // `as` saturates a float-to-int cast, so an absurdly long sample clamps to `u32::MAX` us.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let us = ((latency_ms * 1000.0).round() as u32).max(1);
        let slot = self.cursor.fetch_add(1, Ordering::Relaxed) % LATENCY_RESERVOIR_LEN;
        self.samples[slot].store(us, Ordering::Relaxed);
        self.written.fetch_add(1, Ordering::Release);
    }

    /// The nearest-rank 95th percentile of the held samples, in whole milliseconds rounded UP;
    /// `None` while the ring holds no sample. Answered from the cache while no sample has landed
    /// since it was computed; a sample landing mid-compute moves `written` past the tag, so the
    /// next read computes again.
    #[must_use]
    // The cache's two halves are 32-bit by construction.
    #[allow(clippy::cast_possible_truncation)]
    pub fn p95_ms(&self) -> Option<u64> {
        use std::sync::atomic::Ordering;
        let generation = self.written.load(Ordering::Acquire);
        let cached = self.p95.load(Ordering::Relaxed);
        if (cached >> 32) as u32 == generation {
            return (cached as u32).checked_sub(1).map(u64::from);
        }
        let mut held = [0u32; LATENCY_RESERVOIR_LEN];
        let mut n = 0;
        for s in &self.samples {
            let v = s.load(Ordering::Relaxed);
            if v != 0 {
                held[n] = v;
                n += 1;
            }
        }
        let p95 = (n > 0).then(|| {
            let held = &mut held[..n];
            held.sort_unstable();
            held[(n * 95).div_ceil(100) - 1].div_ceil(1000)
        });
        self.p95.store(
            (u64::from(generation) << 32) | u64::from(p95.map_or(0, |v| v + 1)),
            Ordering::Relaxed,
        );
        p95.map(u64::from)
    }
}

/// EACH MEMBER'S STANDING AS THE RANKING HOOKS READ IT, off the generation's lane store, as 1.5.5's
/// candidate projection read it: the latency signal, the free concurrency (the member's own permits
/// where its `max_concurrent` is stated, the lane's otherwise), the remaining lifetime budget, the
/// breaker state and error rate in the routing pool, and the lane's p95 reservoir.
pub struct ModelSignals {
    app: LiveApp,
    permits: Arc<crate::root::egress_ports::MemberPermits>,
    reservoirs: Arc<HashMap<usize, LatencyReservoir>>,
}

impl busbar_kernel::plane_driver::MemberSignals for ModelSignals {
    fn standing(
        &self,
        pool: &str,
        destination: DestinationId,
    ) -> busbar_kernel::plane_driver::MemberStanding {
        let (app, lane) = (self.app.load(), lane_of(destination));
        let store = &app.store;
        let state = match store.breaker_state_snapshot_in(pool, lane) {
            busbar_kernel::store::BreakerState::Closed => "closed",
            busbar_kernel::store::BreakerState::Open { .. } => "open",
            busbar_kernel::store::BreakerState::HalfOpen => "half_open",
        };
        busbar_kernel::plane_driver::MemberStanding {
            latency_ms: store.lane_latency_ms(lane),
            available_concurrency: self
                .permits
                .available(destination)
                .unwrap_or_else(|| store.available_permits(lane)),
            budget_remaining: store.lane_budget_remaining(lane),
            breaker_state: Some(state),
            error_rate: store.error_rate_in(pool, lane, busbar_kernel::store::now()),
            latency_p95_ms: self
                .reservoirs
                .get(&lane)
                .and_then(LatencyReservoir::p95_ms),
        }
    }
}

/// What the hooks are shown of the model-serving pools beside the walk: each pool's member meta
/// and the members' live standing.
pub struct ModelShown {
    /// Each pool's member meta, by pool.
    pub described: BTreeMap<String, Arc<HashMap<String, busbar_kernel::plane_driver::MemberFacts>>>,
    /// The members' live standing.
    pub signals: Arc<dyn busbar_kernel::plane_driver::MemberSignals>,
}

/// What the lane cells are sealed over beside the App: each pool's ladder as the store's record
/// calls take it, and the pools that are a model a route names directly.
struct CellPlan {
    records: HashMap<String, busbar_kernel::store::BreakerCfg>,
    direct: HashSet<String>,
}

/// One App and its lane store's breaker unit, resolved together.
struct Bound {
    app: Arc<busbar_kernel::state::App>,
    unit: Arc<busbar_kernel_breaker::BreakerUnit>,
}

impl Bound {
    fn of(app: Arc<busbar_kernel::state::App>) -> Arc<Self> {
        Arc::new(Bound {
            unit: app.store.breaker_unit(),
            app,
        })
    }
}

/// The kernel's breaker port over the live App's lane store, for one walk: a model-named direct
/// route is mapped onto the lane-default cell, every read is the lane store's breaker unit's own,
/// and every outcome is recorded through the store's own record calls (the lane's counters move
/// with its cells). The App is resolved once at the walk's start and kept while it is the live
/// one; a config apply mid-walk is seen at the next call, which moves to the new App, so every
/// call lands on the store the live configuration answers then.
struct WalkCells {
    live: LiveApp,
    bound: arc_swap::ArcSwap<Bound>,
    plan: Arc<CellPlan>,
}

impl WalkCells {
    fn over(live: LiveApp, plan: Arc<CellPlan>) -> Self {
        WalkCells {
            bound: arc_swap::ArcSwap::new(Bound::of(live.load())),
            live,
            plan,
        }
    }

    /// The App and unit this call lands on: the walk's, unless the live App has moved since.
    fn bound(&self) -> arc_swap::Guard<Arc<Bound>> {
        let bound = self.bound.load();
        if self.live.is_current(&bound.app) {
            return bound;
        }
        self.bound.store(Bound::of(self.live.load()));
        self.bound.load()
    }

    fn cell<'p>(&self, pool: &'p str) -> &'p str {
        if self.plan.direct.contains(pool) {
            ""
        } else {
            pool
        }
    }
}

/// The lane a destination of this egress names (its destination is the model's lane index).
fn lane_of(destination: DestinationId) -> usize {
    usize::try_from(destination.get()).unwrap_or(usize::MAX)
}

impl Breaker for WalkCells {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        adapters::try_admit(&self.bound().unit, self.cell(pool), destination, now)
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        adapters::ready(&self.bound().unit, self.cell(pool), destination, now, token)
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        adapters::admissible(&self.bound().unit, destination)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        adapters::cooldown_remaining(&self.bound().unit, self.cell(pool), destination, now, token)
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        adapters::classify(status)
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        self.observe_stated(pool, destination, outcome, None, now, token)
    }

    /// The outcome recorded with the reason the plane's reading states, verbatim: a hard-down's
    /// down reason (the lane's `dead_reason` and its operator diagnostic) is the plane's words, as
    /// 1.5.5's classifier wrote its own; with none stated, the outcome's own name.
    fn observe_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        reason: Option<&str>,
        now: u64,
        _token: &Pass<Route>,
    ) -> bool {
        let cell = self.cell(pool);
        let bound = self.bound();
        let (store, lane) = (&bound.app.store, lane_of(destination));
        // The caller's own fault (the one answer the far end records as nothing): counted on the
        // lane, its breaker untouched, whatever its pool configured (1.5.5's `record_outcome`
        // `ClientFault` arm). The far end records through this call alone, so the count is here.
        if matches!(outcome, Outcome::RecordNothing) {
            store.record_client_fault(lane);
            return false;
        }
        let Some(cfg) = self.plan.records.get(cell) else {
            return false;
        };
        match outcome {
            // At the walk's `now`, the instant its admission and its shed read: the outcome a
            // success or a failure pushes into the error-rate window, the cooldown a failure arms
            // and the wait a shed advertises are one clock's, as 1.5.5's record took its
            // `now_time`.
            Outcome::Success => {
                store.record_success_in(cell, lane, now);
                false
            }
            Outcome::Transient { retry_after } => {
                store.record_transient_in_at(cell, lane, now, cfg, retry_after)
            }
            Outcome::HardDown => {
                store.record_hard_down_all_cells(lane, reason.unwrap_or("hard_down"), now)
            }
            // Counted as the caller's fault above.
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
        let classified = adapters::classify(status);
        // The far end's number in the kernel's first reserved numbering (the one the previous
        // release's ladder reads its 429 and 4xx in), read as the kernel's far end reads it.
        let code = status.code.and_then(|c| {
            c.in_namespace(busbar_contract::transport::registry::status_ns::RESERVED[0])
        });
        let cell = self.cell(pool);
        let lane = lane_of(destination);
        let tripped = match (classified.outcome, code) {
            // The previous release's rate-limit record: its own ladder step, the far end's wait
            // honoured.
            (Outcome::Transient { retry_after }, Some(429)) => match self.plan.records.get(cell) {
                Some(cfg) => {
                    self.bound()
                        .app
                        .store
                        .record_rate_limit_in(cell, lane, now, cfg, retry_after)
                }
                None => false,
            },
            // The caller's own fault is counted by `observe`, the one call the far end records
            // through.
            (outcome, _) => self.observe(pool, destination, outcome, now, token),
        };
        (classified, tripped)
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.bound()
            .app
            .store
            .lane_needs_probe(lane_of(destination), now)
    }

    /// A health probe's answer, recorded as 1.5.5's prober recorded it (`engine/health.rs`): a
    /// success recovers the lane in every cell, then joins every cell's window; a transient failure
    /// joins every cell's window under its own pool's ladder; a hard-down parks the lane in every
    /// cell; a client fault records nothing. Every write is at the walk's `now`, the one clock the
    /// walk's own records and reads take (BUSBAR-1.6.0.md l.161).
    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, _token: &Pass<Route>) {
        let bound = self.bound();
        let (store, lane) = (&bound.app.store, lane_of(destination));
        match outcome {
            Outcome::Success => {
                if store.lane_needs_probe(lane, now) {
                    store.recover_lane(lane, now);
                }
                store.record_probe_success_all_cells(lane, now);
            }
            Outcome::Transient { retry_after } => {
                let resolve = |pool: &str| self.plan.records.get(pool).cloned().unwrap_or_default();
                store.record_probe_failure_all_cells(
                    lane,
                    "health-probe",
                    &resolve,
                    retry_after,
                    now,
                );
            }
            Outcome::HardDown => {
                let _ = store.record_hard_down_all_cells(
                    lane,
                    "health-probe hard-down (auth/billing)",
                    now,
                );
            }
            Outcome::RecordNothing => {}
        }
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, _now: u64) {
        self.bound()
            .unit
            .release_probe(self.cell(pool), destination, epoch);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.bound().unit.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.bound().unit.refund_budget(destination);
    }
}

/// The walk's counters on the kernel's telemetry bank, as the previous release's attempt counted
/// them: each member by its lane index, under the pool label the walk names (a pool, or the model a
/// direct route names); the wait-terminal depth as the root's walk counters keep it.
struct ModelTelemetry {
    app: LiveApp,
    queued: crate::root::egress_ports::WalkTelemetry,
    /// Each lane's p95 reservoir, fed only while the generation declares the signal.
    reservoirs: Arc<HashMap<usize, LatencyReservoir>>,
}

impl busbar_kernel_egress::ports::Telemetry for ModelTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::upstream_attempt(&self.app.load(), pool, lane_of(destination));
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str) {
        busbar_kernel::telemetry::upstream_failure(
            &self.app.load(),
            pool,
            lane_of(destination),
            disposition,
        );
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        busbar_kernel::telemetry::failover(&self.app.load(), pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::breaker_trip(&self.app.load(), pool, lane_of(destination));
    }

    fn upstream_latency(&self, destination: DestinationId, ms: f64) {
        // The lane's latency signal (the admin pool listing's `latency_ms`, the `fastest` order's
        // input), as 1.5.5's served attempt recorded it.
        let app = self.app.load();
        let lane = lane_of(destination);
        app.store.record_latency_in("", lane, ms);
        // The same sample into the lane's p95 reservoir, ONLY while the generation declares the
        // signal, as 1.5.5 collected it.
        if app
            .requested_signals
            .wants(busbar_contract::signal::Signal::CandidateLatencyP95Ms)
        {
            if let Some(r) = self.reservoirs.get(&lane) {
                r.record(ms);
            }
        }
    }

    fn queued(&self, pool: &str, delta: i64) {
        busbar_kernel_egress::ports::Telemetry::queued(&self.queued, pool, delta);
        // The scrape's pool-queue gauge reads the depth the kernel's tables report.
        busbar_kernel::plane_driver::route_tables::set_pool_queued_depth(
            pool,
            u64::try_from(self.queued.depth(pool)).unwrap_or(0),
        );
    }
}

/// THE EGRESS OF THE PLANE SERVING THE `pools` MAP (module doc): one member per sealed entry (its
/// destination the model's lane index, its name the model's), a pool per configured pool with its
/// own bounds and terminal, a pool per model a route may name directly, the kernel's breaker cells
/// under each pool's ladder, each model's concurrency cap, the node's counters, `journal` and
/// `clock`, the walk's clock the plane was composed on (the node's,
/// [`crate::root::egress_ports::NodeClock`]): the cooldown a failure
/// arms is recorded at the walk's reading of it, so the wait a shed advertises is measured on the
/// same clock.
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
    clock: Arc<dyn busbar_kernel_egress::ports::Clock>,
    stream_ceiling_secs: u64,
) -> Result<(busbar_kernel::plane_driver::Egress, ModelShown), String> {
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
    let permits = Arc::new(crate::root::egress_ports::MemberPermits::new(limits));
    let reservoirs: Arc<HashMap<usize, LatencyReservoir>> = Arc::new(
        serving
            .lanes
            .values()
            .map(|lane| (*lane, LatencyReservoir::default()))
            .collect(),
    );
    let shown = ModelShown {
        described: plan.meta.clone(),
        signals: Arc::new(ModelSignals {
            app: serving.app.clone(),
            permits: Arc::clone(&permits),
            reservoirs: Arc::clone(&reservoirs),
        }),
    };
    let cells = Arc::new(CellPlan {
        records: plan.records.clone(),
        direct,
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
                queued: crate::root::egress_ports::WalkTelemetry::new(names),
                reservoirs,
            }),
            pools: built,
            routes: sealed,
            stream_ceiling_secs,
            stated_ceiling_secs: facts.stream_ceiling_secs,
            error_body_max: busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
        },
        shown,
    ))
}

#[cfg(test)]
#[path = "tests/model_egress.rs"]
mod tests;
