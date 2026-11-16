// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::caps::{Pass, Route};
use busbar_contract::dest::DestinationId;
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, Outcome, Unavailable, UpstreamStatus,
};
use busbar_kernel_egress::{Failover, OnExhausted};
use foldhash::{HashMap, HashSet};

use crate::root::adapters;

/// The kernel's App, as the live configuration answers it (a config apply rebuilds it, its lane
/// store and its telemetry bank with it): the swap handle once boot has made one, the App the
/// egress was composed with until then.
#[derive(Clone)]
pub struct LiveApp {
    handle: Arc<std::sync::OnceLock<std::sync::Weak<busbar_kernel::state::AppHandle>>>,
    fallback: AppFallback,
}

#[derive(Clone)]
enum AppFallback {
    Borrowed(std::sync::Weak<busbar_kernel::state::App>),
    #[cfg(test)]
    Fixed(Arc<busbar_kernel::state::App>),
}

impl AppFallback {
    fn load(&self) -> Option<Arc<busbar_kernel::state::App>> {
        match self {
            Self::Borrowed(app) => app.upgrade(),
            #[cfg(test)]
            Self::Fixed(app) => Some(Arc::clone(app)),
        }
    }
}

impl LiveApp {
    #[must_use]
    pub fn new(
        handle: Arc<std::sync::OnceLock<std::sync::Weak<busbar_kernel::state::AppHandle>>>,
        fallback: &Arc<busbar_kernel::state::App>,
    ) -> Self {
        LiveApp {
            handle,
            fallback: AppFallback::Borrowed(Arc::downgrade(fallback)),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn fixed(app: Arc<busbar_kernel::state::App>) -> Self {
        LiveApp {
            handle: Arc::default(),
            fallback: AppFallback::Fixed(app),
        }
    }

    #[must_use]
    pub fn load(&self) -> Arc<busbar_kernel::state::App> {
        self.try_load()
            .expect("the serving application owner has retired")
    }

    #[must_use]
    pub(crate) fn try_load(&self) -> Option<Arc<busbar_kernel::state::App>> {
        match self.handle.get() {
            Some(handle) => handle.upgrade().map(|handle| handle.load()),
            None => self.fallback.load(),
        }
    }

    fn is_current(&self, app: &Arc<busbar_kernel::state::App>) -> bool {
        match self.handle.get() {
            Some(h) => h
                .upgrade()
                .is_some_and(|handle| Arc::ptr_eq(&handle.snapshot(), app)),
            None => self
                .fallback
                .load()
                .is_some_and(|fallback| Arc::ptr_eq(&fallback, app)),
        }
    }
}

/// One configured pool: its members (model, weight, attempt timeout), failover bounds and
/// exhaustion terminal.
#[derive(Debug, Clone)]
pub(crate) struct ModelPool {
    pub(crate) members: Vec<(String, u32, Option<u64>)>,
    pub(crate) failover: Failover,
    pub(crate) on_exhausted: OnExhausted,
    /// Its members are reached with the caller's own credential (the pool's
    /// `upstream_credentials:`, else the all-pools default, is `passthrough`).
    pub(crate) passthrough: bool,
}

/// One model's own bounds: its concurrency cap, its attempt timeout and its context window.
#[derive(Debug, Clone, Default)]
pub(crate) struct ModelLane {
    pub(crate) max_concurrent: Option<usize>,
    pub(crate) attempt_timeout_ms: Option<u64>,
    pub(crate) context_max: Option<usize>,
}

/// THE MODEL-SERVING POOLS as the configuration resolved them, captured before the configuration
/// is consumed: every pool and model bound the walk honours, and the breaker ladder of each pool.
#[derive(Debug, Clone, Default)]
pub struct ModelPools {
    pub(crate) pools: BTreeMap<String, ModelPool>,
    pub(crate) lanes: BTreeMap<String, ModelLane>,
    /// The all-pools `upstream_credentials:` default is `passthrough`: a route naming a model
    /// directly reaches it with the caller's own credential.
    pub(crate) passthrough: bool,
    /// Each pool's ladder as the lane store's record calls take it (the previous release's
    /// `resolve_breaker_cfg`: the pool's own, else the default); `""` = the lane-default cell's.
    pub(crate) records: Arc<HashMap<Arc<str>, busbar_kernel::store::BreakerCfg>>,
    /// Each model's active health probing (K7): its provider's `health:` over the process-wide
    /// defaults, as 1.5.5's prober resolved it per lane.
    pub(crate) probes: BTreeMap<String, busbar_kernel::probe::ProbeCfg>,
    /// What each pool's members show the ranking hooks, by pool then model: the member's tier and
    /// tags, and its model's cost per million tokens off the rate card (1.5.5's pool member meta).
    pub(crate) meta: Arc<BTreeMap<String, Arc<MemberFactsByModel>>>,
}

/// The member facts by model, in the map type the kernel's far end takes them as.
pub(crate) type MemberFactsByModel =
    std::collections::HashMap<String, busbar_kernel::plane_driver::MemberFacts>;

pub struct ModelServing {
    pub pools: ModelPools,

    pub lanes: HashMap<String, usize>,

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
    pub fn record(&self, latency_ms: f64) {
        use std::sync::atomic::Ordering;
        if !latency_ms.is_finite() || latency_ms <= 0.0 {
            return;
        }

        let us = ((latency_ms * 1000.0).round() as u32).max(1);
        let slot = self.cursor.fetch_add(1, Ordering::Relaxed) % LATENCY_RESERVOIR_LEN;
        self.samples[slot].store(us, Ordering::Relaxed);
        self.written.fetch_add(1, Ordering::Release);
    }

    #[must_use]
    pub(crate) fn p95_ms(&self) -> Option<u64> {
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
            // The p95 is one order statistic: select it (O(n)), no request-path sort.
            let (_, p95, _) = held[..n].select_nth_unstable((n * 95).div_ceil(100) - 1);
            p95.div_ceil(1000)
        });
        self.p95.store(
            (u64::from(generation) << 32) | u64::from(p95.map_or(0, |v| v + 1)),
            Ordering::Relaxed,
        );
        p95.map(u64::from)
    }
}

pub struct ModelSignals {
    pub(crate) app: LiveApp,
    pub(crate) names: Arc<HashMap<DestinationId, String>>,
    pub(crate) permits: Arc<crate::root::egress_ports::MemberPermits>,
    pub(crate) reservoirs: Arc<HashMap<usize, LatencyReservoir>>,
}

impl busbar_kernel::plane_driver::MemberSignals for ModelSignals {
    fn standing(
        &self,
        pool: &str,
        destination: DestinationId,
    ) -> busbar_kernel::plane_driver::MemberStanding {
        let app = self.app.load();
        let Some(lane) = model_lane(&app, &self.names, destination) else {
            return busbar_kernel::plane_driver::MemberStanding {
                breaker_state: Some("open"),
                budget_remaining: Some(0),
                ..Default::default()
            };
        };
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
                .get(&lane_of(destination))
                .and_then(LatencyReservoir::p95_ms),
        }
    }
}

pub(crate) struct ModelShown {
    pub described: Arc<BTreeMap<String, Arc<MemberFactsByModel>>>,

    pub signals: Arc<dyn busbar_kernel::plane_driver::MemberSignals>,
}

pub(crate) struct CellPlan {
    pub(crate) records: Arc<HashMap<Arc<str>, busbar_kernel::store::BreakerCfg>>,
    pub(crate) direct: HashSet<String>,
    pub(crate) names: Arc<HashMap<DestinationId, String>>,
}

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

type SpentBudgets =
    HashMap<DestinationId, Vec<(Arc<busbar_kernel_breaker::BreakerUnit>, DestinationId)>>;

pub(crate) struct WalkCells {
    live: LiveApp,
    bound: arc_swap::ArcSwap<Bound>,
    plan: Arc<CellPlan>,
    probes: std::sync::Mutex<HashMap<u64, HeldProbe>>,
    next_probe: std::sync::atomic::AtomicU64,
    budgets: std::sync::Mutex<SpentBudgets>,
}

struct HeldProbe {
    unit: Arc<busbar_kernel_breaker::BreakerUnit>,
    pool: Arc<str>,
    destination: DestinationId,
    epoch: u64,
}

impl Drop for HeldProbe {
    fn drop(&mut self) {
        self.unit
            .release_probe(&self.pool, self.destination, self.epoch);
    }
}

impl WalkCells {
    pub(crate) fn over(live: LiveApp, plan: Arc<CellPlan>) -> Self {
        WalkCells {
            bound: arc_swap::ArcSwap::new(Bound::of(live.load())),
            live,
            plan,
            probes: std::sync::Mutex::default(),
            next_probe: std::sync::atomic::AtomicU64::new(0),
            budgets: std::sync::Mutex::default(),
        }
    }

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

    /// The cell's name, shared from the plan's ladder keys: no copy per held probe.
    fn cell_name(&self, pool: &str) -> Arc<str> {
        let cell = self.cell(pool);
        match self.plan.records.get_key_value(cell) {
            Some((name, _)) => Arc::clone(name),
            None => crate::root::cold::unplanned_cell_name(cell),
        }
    }

    fn destination(&self, bound: &Bound, destination: DestinationId) -> Option<DestinationId> {
        model_lane(&bound.app, &self.plan.names, destination)
            .map(|lane| DestinationId::new(lane as u64))
    }
}

fn model_lane(
    app: &busbar_kernel::state::App,
    names: &HashMap<DestinationId, String>,
    destination: DestinationId,
) -> Option<usize> {
    let model = names.get(&destination)?;
    let tables = app.engine_tables_view();
    tables
        .model_index(model)
        .filter(|&lane| lane < tables.lane_count())
}

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
        let bound = self.bound();
        let translated = self
            .destination(&bound, destination)
            .ok_or(Unavailable::Dead)?;
        let mut admit = adapters::try_admit(&bound.unit, self.cell(pool), translated, now)?;
        if let Some(epoch) = admit.probe_epoch {
            let held = HeldProbe {
                unit: Arc::clone(&bound.unit),
                pool: self.cell_name(pool),
                destination: translated,
                epoch,
            };
            let ticket = self
                .next_probe
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_add(1),
                )
                .map_err(|_| Unavailable::ProbeInFlight)?
                .saturating_add(1);
            self.probes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(ticket, held);
            admit.probe_epoch = Some(ticket);
        }
        Ok(admit)
    }

    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        let bound = self.bound();
        let Some(translated) = self.destination(&bound, destination) else {
            return Some(Unavailable::Dead);
        };
        adapters::unavailable(&bound.unit, self.cell(pool), translated, now, token)
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        let bound = self.bound();
        self.destination(&bound, destination)
            .is_some_and(|translated| {
                adapters::ready(&bound.unit, self.cell(pool), translated, now, token)
            })
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        let bound = self.bound();
        self.destination(&bound, destination)
            .is_some_and(|translated| adapters::admissible(&bound.unit, translated))
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        let bound = self.bound();
        self.destination(&bound, destination)
            .map_or(0, |translated| {
                adapters::cooldown_remaining(&bound.unit, self.cell(pool), translated, now, token)
            })
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        adapters::classify(&status)
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
        let Some(translated) = self.destination(&bound, destination) else {
            return false;
        };
        let (store, lane) = (&bound.app.store, lane_of(translated));

        if matches!(outcome, Outcome::RecordNothing) {
            store.record_client_fault(lane);
            return false;
        }
        let Some(cfg) = self.plan.records.get(cell) else {
            return false;
        };
        match outcome {
            Outcome::Success => {
                store.record_success_in(cell, lane, now);
                false
            }
            Outcome::RateLimit { retry_after } => {
                store.record_rate_limit_in(cell, lane, now, cfg, retry_after)
            }
            Outcome::Transient { retry_after } => {
                store.record_transient_in_at(cell, lane, now, cfg, retry_after)
            }
            Outcome::HardDown => {
                store.record_hard_down_all_cells(lane, reason.unwrap_or("hard_down"), now)
            }

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
        let classified = adapters::classify(&status);
        let tripped = self.observe(pool, destination, classified.outcome, now, token);
        (classified, tripped)
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        let bound = self.bound();
        self.destination(&bound, destination)
            .is_some_and(|translated| bound.app.store.lane_needs_probe(lane_of(translated), now))
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, _token: &Pass<Route>) {
        let bound = self.bound();
        let Some(translated) = self.destination(&bound, destination) else {
            return;
        };
        let (store, lane) = (&bound.app.store, lane_of(translated));
        match outcome {
            Outcome::Success => {
                if store.lane_needs_probe(lane, now) {
                    store.recover_lane(lane, now);
                }
                store.record_probe_success_all_cells(lane, now);
            }
            Outcome::Transient { retry_after } | Outcome::RateLimit { retry_after } => {
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
                if !store.record_hard_down_all_cells(
                    lane,
                    "health-probe hard-down (auth/billing)",
                    now,
                ) {
                    tracing::warn!(lane, "health-probe hard-down recording had no effect");
                }
            }
            Outcome::RecordNothing => {}
        }
    }

    fn release_probe(&self, _pool: &str, _destination: DestinationId, epoch: u64, _now: u64) {
        let held = self
            .probes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&epoch);

        drop(held);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        let bound = self.bound();
        let Some(translated) = self.destination(&bound, destination) else {
            return false;
        };
        if !bound.unit.spend_budget(translated) {
            return false;
        }
        self.budgets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(destination)
            .or_default()
            .push((Arc::clone(&bound.unit), translated));
        true
    }

    fn refund_budget(&self, destination: DestinationId) {
        let held = self
            .budgets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&destination)
            .and_then(Vec::pop);
        if let Some((unit, translated)) = held {
            unit.refund_budget(translated);
        }
    }
}

pub(crate) struct ModelTelemetry {
    pub(crate) app: LiveApp,
    pub(crate) names: Arc<HashMap<DestinationId, String>>,
    pub(crate) queued: crate::root::egress_ports::WalkTelemetry,

    pub(crate) reservoirs: Arc<HashMap<usize, LatencyReservoir>>,
}

impl busbar_kernel_egress::ports::Telemetry for ModelTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        let app = self.app.load();
        if let Some(lane) = model_lane(&app, &self.names, destination) {
            busbar_kernel::telemetry::upstream_attempt(&app, pool, lane);
        }
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str) {
        let app = self.app.load();
        let Some(lane) = model_lane(&app, &self.names, destination) else {
            return;
        };
        busbar_kernel::telemetry::upstream_failure(&app, pool, lane, disposition);
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        busbar_kernel::telemetry::failover(&self.app.load(), pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        let app = self.app.load();
        if let Some(lane) = model_lane(&app, &self.names, destination) {
            busbar_kernel::telemetry::breaker_trip(&app, pool, lane);
        }
    }

    fn upstream_latency(&self, destination: DestinationId, ms: f64) {
        let app = self.app.load();
        let Some(lane) = model_lane(&app, &self.names, destination) else {
            return;
        };
        app.store.record_latency_in("", lane, ms);
        busbar_kernel::telemetry::lane_request_finished(&app, lane, ms / 1000.0);

        if app
            .requested_signals
            .wants(busbar_contract::signal::Signal::CandidateLatencyP95Ms)
        {
            if let Some(r) = self.reservoirs.get(&lane_of(destination)) {
                r.record(ms);
            }
        }
    }

    fn queued(&self, pool: &str, delta: i64) {
        busbar_kernel_egress::ports::Telemetry::queued(&self.queued, pool, delta);

        busbar_kernel::plane_driver::route_tables::change_pool_queued_depth(pool, delta);
    }
}

pub use crate::root::off_path::model_egress::compose;

#[cfg(test)]
#[path = "tests/model_egress.rs"]
mod tests;
