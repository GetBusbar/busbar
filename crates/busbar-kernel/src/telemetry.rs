// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::sync::OnceLock;

use crate::state::App;

/// The banked slots for one request family: `busbar_requests_total` (per outcome) and
/// `busbar_request_duration_seconds`, for a fixed `(ingress_protocol, pool)` pair ON THE PLANE THIS
/// BANK REGISTERS (see [`AppSlots::build`]).
#[derive(Clone, Copy)]
pub(crate) struct RequestFamily {
    pub(crate) requests: [CounterSlot; OUTCOMES.len()],
    pub(crate) duration: HistogramSlot,
    pub(crate) producer_duration: [HistogramSlot; OUTCOMES.len()],
}

/// The banked slots for one mounted plane and declared dialect, at the fixed unresolved pool label
/// mounted ingress observes: `busbar_plane_requests_total` (per outcome),
/// `busbar_plane_request_duration_seconds`, and the response-ready phase histogram.
#[derive(Clone, Copy)]
pub(crate) struct MountedFamily {
    pub(crate) requests: [CounterSlot; OUTCOMES.len()],
    pub(crate) duration: HistogramSlot,
    pub(crate) phase: [HistogramSlot; OUTCOMES.len()],
}

/// The banked slots for one `(pool label, lane)` pair on the upstream walk:
/// attempts, per-disposition failures, and breaker trips.
#[derive(Clone, Copy)]
pub(crate) struct LaneFamily {
    pub(crate) attempts: CounterSlot,
    pub(crate) failures: [CounterSlot; DISPOSITIONS.len()],
    pub(crate) trips: CounterSlot,
}

/// All hot-path metric slots for ONE `App` snapshot, resolved at config load (`App` construction)
/// so the request path never interns, allocates, or touches the recorder registry. Lookups are
/// read-only probes into maps owned by the (immutable) `App` — no shared-cache-line writes.
///
/// Every lookup method returns the slots for values in THIS generation's bounded label space; a
/// miss (custom protocol, label from a different generation, bare test `App`) falls back to the
/// exact macro emission the site used before the bank, so `/metrics` output is preserved always.
#[derive(Default)]
pub(crate) struct AppSlots {
    /// The plane this bank's request families belong to. The bank's inputs (`lanes`, `pools`,
    /// `by_model`) are the MODEL plane's routing tables, so a request from any other plane must
    /// miss the bank and take a different emission path — it is carried as a field rather than
    /// assumed at the lookup so that guard is explicit. Note the banked `busbar_requests_total` /
    /// `busbar_request_duration_seconds` families carry NO `plane` label (they are the model
    /// plane's v1.5.4-identical series); the mounted planes emit their own `busbar_plane_*`
    /// families from `request_finished` instead.
    pub(crate) banked_plane: &'static str,
    /// pool label (ingress convention: pools ∪ models ∪ "unresolved") → per-dialect request
    /// families, indexed by position in the banked plane's declared dialects
    /// ([`declared_dialects`]).
    pub(crate) request: HashMap<Box<str>, Box<[RequestFamily]>>,
    /// engine pool label (pools ∪ models, matching `proxy::metric_pool_label`) → lane idx → family.
    pub(crate) lane: HashMap<Box<str>, HashMap<usize, LaneFamily>>,
    /// engine pool label → failover-reason slots, indexed by position in [`REASONS`].
    pub(crate) failover: HashMap<Box<str>, [CounterSlot; REASONS.len()]>,
    /// mounted plane key → families, indexed by position in that plane's declared dialects.
    pub(crate) mounted: HashMap<&'static str, Box<[MountedFamily]>>,
    /// lane idx -> `busbar_lane_request_duration_seconds` slot. Keyed by the lane id alone, so the
    /// request path hashes no label; `pool`, `target`, `model` and `instance` were attached when
    /// the slot was interned at build, from the lane table.
    pub(crate) lane_duration: Box<[HistogramSlot]>,
}

impl AppSlots {
    fn request_family(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
    ) -> Option<&RequestFamily> {
        if plane != self.banked_plane {
            return None;
        }
        let proto_idx = declared_dialects(self.banked_plane)
            .iter()
            .position(|p| *p == ingress_protocol)?;
        self.request.get(pool).map(|fams| &fams[proto_idx])
    }

    fn mounted_family(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
    ) -> Option<&MountedFamily> {
        if pool != POOL_LABEL_UNRESOLVED {
            return None;
        }
        let proto_idx = declared_dialects(plane)
            .iter()
            .position(|p| *p == ingress_protocol)?;
        self.mounted.get(plane)?.get(proto_idx)
    }

    fn lane_family(&self, pool_label: &str, lane_idx: usize) -> Option<&LaneFamily> {
        self.lane.get(pool_label)?.get(&lane_idx)
    }
}

/// A lane's request finished in `seconds`: one push into the lane's own histogram slot. A lane
/// outside this generation's table records nothing.
pub fn lane_request_finished(app: &App, lane_idx: usize, seconds: f64) {
    if let Some(slot) = app.tslots.lane_duration.get(lane_idx) {
        if slot.is_valid() {
            slot.record(seconds);
        }
    }
}

/// `telemetry.max_lane_series`: lanes beyond it fold into `target="other"`.
static MAX_LANE_SERIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(crate::config::limits::DEFAULT_TELEMETRY_MAX_LANE_SERIES);

static LANE_SERIES_DROPPED: AtomicU64 = AtomicU64::new(0);

pub fn set_max_lane_series(max: usize) {
    MAX_LANE_SERIES.store(max, Ordering::Relaxed);
}

pub(crate) fn max_lane_series() -> usize {
    MAX_LANE_SERIES.load(Ordering::Relaxed)
}

/// `dropped.lane_series`: lanes folded into `target="other"` since boot.
#[must_use]
pub fn lane_series_dropped() -> u64 {
    LANE_SERIES_DROPPED.load(Ordering::Relaxed)
}

pub(crate) fn count_lane_series_dropped(n: u64) {
    LANE_SERIES_DROPPED.fetch_add(n, Ordering::Relaxed);
}

/// `busbar_unit_refusals_total{reason,instance}`: `reason` is a closed unit reason, equal to the
/// unit record's `reason.code`.
pub fn unit_refusal_on(instance: &str, reason: &'static str) {
    if !bump_kept(&UNBANKED_UNIT_REFUSALS, instance, reason) {
        crate::cold::host::telemetry_unit_refusal_first(instance, reason);
    }
}

pub(crate) fn request_finished(
    app: &App,
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
    seconds: f64,
) {
    request_finished_in(&app.tslots, plane, ingress_protocol, pool, outcome, seconds);
}

fn request_finished_in(
    slots: &AppSlots,
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
    seconds: f64,
) {
    let outcome_idx = OUTCOMES.iter().position(|o| *o == outcome);
    if !crate::plane_driver::dispatch::is_fallback(plane) {
        let fam = slots.mounted_family(plane, ingress_protocol, pool);
        if crate::snapshot::retaining() {
            record_phase_duration(fam.map(|fam| fam.phase), outcome, seconds);
        }
        match (fam, outcome_idx) {
            (Some(fam), Some(oi)) if fam.requests[oi].is_valid() => fam.requests[oi].incr(),
            _ => crate::snapshot::incr_plane_requests_total(plane, ingress_protocol, pool, outcome),
        }
        match fam {
            Some(fam) if fam.duration.is_valid() => fam.duration.record(seconds),
            _ => crate::snapshot::record_plane_request_duration(
                plane,
                ingress_protocol,
                pool,
                seconds,
            ),
        }
        return;
    }

    let fam = slots.request_family(plane, ingress_protocol, pool);
    match (fam, outcome_idx) {
        (Some(fam), Some(oi)) if fam.requests[oi].is_valid() => fam.requests[oi].incr(),
        _ => crate::snapshot::incr_requests_total(ingress_protocol, pool, outcome),
    }
    match fam {
        Some(fam) if fam.duration.is_valid() => fam.duration.record(seconds),
        _ => crate::snapshot::record_request_duration(ingress_protocol, pool, seconds),
    }
}

pub fn model_request_finished(
    app: &App,
    ingress_protocol: &str,
    pool: &str,
    status: u16,
    seconds: f64,
    unit_id: Option<&dyn std::fmt::Display>,
) {
    let outcome = model_request_finished_in(&app.tslots, ingress_protocol, pool, status, seconds);

    if app
        .export_projections
        .wants_stream(busbar_contract::export_stream::ExportStream::Logs)
    {
        let correlation_id = unit_id.map(ToString::to_string);
        crate::export::deliver_request_log(
            &app.exports,
            &crate::export::RequestLogFacts {
                correlation_id: correlation_id.as_deref(),
                ts: busbar_kernel::store::now(),
                ingress_protocol,
                pool,
                outcome,
                latency_ms: (seconds * 1000.0) as u64,
            },
        );
    }
}

fn model_request_finished_in(
    slots: &AppSlots,
    ingress_protocol: &str,
    pool: &str,
    status: u16,
    seconds: f64,
) -> &'static str {
    let outcome = outcome_of(status);
    if crate::snapshot::retaining() {
        record_phase_duration(
            slots
                .request_family(
                    crate::plane_driver::dispatch::fallback_key(),
                    ingress_protocol,
                    pool,
                )
                .map(|family| family.producer_duration),
            outcome,
            seconds,
        );
    }
    request_finished_in(
        slots,
        crate::plane_driver::dispatch::fallback_key(),
        ingress_protocol,
        pool,
        outcome,
        seconds,
    );
    outcome
}

pub fn upstream_attempt(app: &App, pool_label: &str, lane_idx: usize) {
    upstream_attempt_in(&app.tslots, pool_label, lane_idx, || {
        upstream_attempt_on(
            pool_label,
            app.engine_tables_view()
                .lane_view(lane_idx)
                .map(|lane| lane.model)
                .unwrap_or(""),
        )
    });
}

fn upstream_attempt_in(
    slots: &AppSlots,
    pool_label: &str,
    lane_idx: usize,
    fallback: impl FnOnce(),
) {
    match slots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.attempts.is_valid() => fam.attempts.incr(),
        _ => fallback(),
    }
}

pub fn upstream_failure(app: &App, pool_label: &str, lane_idx: usize, disposition: &'static str) {
    upstream_failure_in(&app.tslots, pool_label, lane_idx, disposition, || {
        upstream_failure_on(
            pool_label,
            app.engine_tables_view()
                .lane_view(lane_idx)
                .map(|lane| lane.model)
                .unwrap_or(""),
            disposition,
        )
    });
}

fn upstream_failure_in(
    slots: &AppSlots,
    pool_label: &str,
    lane_idx: usize,
    disposition: &'static str,
    fallback: impl FnOnce(),
) {
    let fam = slots.lane_family(pool_label, lane_idx);
    let di = DISPOSITIONS.iter().position(|d| *d == disposition);
    match (fam, di) {
        (Some(fam), Some(di)) if fam.failures[di].is_valid() => fam.failures[di].incr(),
        _ => fallback(),
    }
}

pub fn breaker_trip(app: &App, pool_label: &str, lane_idx: usize) {
    breaker_trip_in(&app.tslots, pool_label, lane_idx, || {
        breaker_trip_on(
            pool_label,
            app.engine_tables_view()
                .lane_view(lane_idx)
                .map(|lane| lane.model)
                .unwrap_or(""),
        )
    });
}

fn breaker_trip_in(slots: &AppSlots, pool_label: &str, lane_idx: usize, fallback: impl FnOnce()) {
    match slots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.trips.is_valid() => fam.trips.incr(),
        _ => fallback(),
    }
}

pub fn failover(app: &App, pool_label: &str, reason: &'static str) {
    failover_in(&app.tslots, pool_label, reason);
}

fn failover_in(slots: &AppSlots, pool_label: &str, reason: &'static str) {
    let slots = slots.failover.get(pool_label);
    let ri = REASONS.iter().position(|r| *r == reason);
    match (slots, ri) {
        (Some(slots), Some(ri)) if slots[ri].is_valid() => slots[ri].incr(),
        _ => failover_on(pool_label, reason),
    }
}

/// A map keyed by one label value.
pub(crate) type LabelMap<V> = HashMap<Box<str>, V>;

/// Process-wide recorder state for the unbanked emissions, keyed by label value.
pub(crate) type Handles<V> = std::sync::LazyLock<RwLock<LabelMap<V>>>;

// The unbanked emissions (a label set outside this generation's bank, or a caller with no bank)
// keep the recorder handle each label set registered: a hit borrows the caller's labels and
// allocates nothing; the first sight of a label set registers it once, in the cold module. Only
// counters are kept: the recorder never deletes a counter, so a kept handle stays live (an idle
// gauge is deleted, so the pool-depth gauge keeps its interned label value instead).

/// `busbar_breaker_trips_total`: pool → lane → handle.
pub(crate) static UNBANKED_BREAKER_TRIPS: Handles<LabelMap<metrics::Counter>> =
    std::sync::LazyLock::new(RwLock::default);
/// `busbar_failovers_total`: pool → reason → handle.
pub(crate) static UNBANKED_FAILOVERS: Handles<HashMap<&'static str, metrics::Counter>> =
    std::sync::LazyLock::new(RwLock::default);
/// `busbar_upstream_attempts_total`: pool → lane → handle.
pub(crate) static UNBANKED_ATTEMPTS: Handles<LabelMap<metrics::Counter>> =
    std::sync::LazyLock::new(RwLock::default);
/// `busbar_upstream_failures_total`: pool → lane → disposition → handle.
pub(crate) static UNBANKED_FAILURES: Handles<LabelMap<HashMap<&'static str, metrics::Counter>>> =
    std::sync::LazyLock::new(RwLock::default);
/// `busbar_translations_total`: from → to → handle.
pub(crate) static UNBANKED_TRANSLATIONS: Handles<LabelMap<metrics::Counter>> =
    std::sync::LazyLock::new(RwLock::default);
/// `busbar_unit_refusals_total`: instance -> reason -> handle.
pub(crate) static UNBANKED_UNIT_REFUSALS: Handles<LabelMap<metrics::Counter>> =
    std::sync::LazyLock::new(RwLock::default);
/// The pool-depth gauge's interned pool label values.
pub(crate) static POOL_LABELS: Handles<Arc<str>> = std::sync::LazyLock::new(RwLock::default);

/// Bump the kept handle for `(a, b)`; false when that label set has none yet.
fn bump_kept(cache: &Handles<LabelMap<metrics::Counter>>, a: &str, b: &str) -> bool {
    let held = cache.read().unwrap_or_else(|p| p.into_inner());
    match held.get(a).and_then(|inner| inner.get(b)) {
        Some(counter) => {
            counter.increment(1);
            true
        }
        None => false,
    }
}

pub fn breaker_trip_on(pool_label: &str, lane_label: &str) {
    if !bump_kept(&UNBANKED_BREAKER_TRIPS, pool_label, lane_label) {
        crate::cold::host::telemetry_breaker_trip_first(pool_label, lane_label);
    }
}

pub fn failover_on(pool_label: &str, reason: &'static str) {
    {
        let held = UNBANKED_FAILOVERS.read().unwrap_or_else(|p| p.into_inner());
        if let Some(counter) = held.get(pool_label).and_then(|reasons| reasons.get(reason)) {
            counter.increment(1);
            return;
        }
    }
    crate::cold::host::telemetry_failover_first(pool_label, reason);
}

pub fn pool_queued_on(pool_label: &str, depth: i64) {
    let kept = POOL_LABELS
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(pool_label)
        .map(Arc::clone);
    let pool = match kept {
        Some(pool) => pool,
        None => crate::cold::host::telemetry_pool_label(pool_label),
    };
    metrics::gauge!(crate::snapshot::POOL_QUEUED, "pool" => pool).set(depth as f64);
}

pub fn translation(from: &str, to: &str) {
    static SLOTS: OnceLock<Vec<(&'static str, &'static str, CounterSlot)>> = OnceLock::new();
    let table = SLOTS.get_or_init(crate::off_path::telemetry::translation_slots);
    match table
        .iter()
        .find(|(f, t, slot)| *f == from && *t == to && slot.is_valid())
    {
        Some((_, _, slot)) => slot.incr(),
        None => {
            if !bump_kept(&UNBANKED_TRANSLATIONS, from, to) {
                crate::cold::host::telemetry_translation_first(from, to);
            }
        }
    }
}

// Internal observation stream: Source exports exact cumulative integer samples, not a summary.
pub(crate) const REQUEST_PHASE_DURATION: &str = "busbar_request_phase_duration_seconds";
pub(crate) const REQUEST_PHASE_DROPPED: &str = "busbar_request_phase_observations_dropped_total";
pub(crate) const PRODUCER_DRIVE: &str = "LlmProducerDrive";
pub(crate) const RESPONSE_READY: &str = "MountedResponseReady";

pub(crate) fn phase_duration_slot(
    plane: &str,
    phase: &str,
    protocol: &str,
    pool: &str,
) -> [HistogramSlot; OUTCOMES.len()] {
    std::array::from_fn(|i| {
        histogram_slot(
            REQUEST_PHASE_DURATION,
            &[
                ("plane", plane),
                ("phase", phase),
                ("pool", pool),
                ("ingress_protocol", protocol),
                ("outcome", OUTCOMES[i]),
            ],
        )
    })
}

static PHASE_DROPPED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn request_phase_dropped() -> [u64; 2] {
    std::array::from_fn(|i| PHASE_DROPPED[i].load(Ordering::Relaxed))
}

fn record_phase_duration(
    slots: Option<[HistogramSlot; OUTCOMES.len()]>,
    outcome: &str,
    seconds: f64,
) {
    let slot = slots.and_then(|slots| {
        OUTCOMES
            .iter()
            .position(|held| *held == outcome)
            .map(|i| slots[i])
    });
    match slot {
        Some(slot) if slot.is_valid() => slot.record(seconds),
        Some(_) => {
            let _ = PHASE_DROPPED[0].try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
            metrics::counter!(REQUEST_PHASE_DROPPED, "reason" => "histogram_capacity").increment(1)
        }
        None => {
            let _ = PHASE_DROPPED[1].try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
            metrics::counter!(REQUEST_PHASE_DROPPED, "reason" => "unregistered_labels").increment(1)
        }
    }
}

pub(crate) fn declared_dialects(plane: &str) -> &'static [&'static str] {
    crate::plane_driver::registry::plane_decl_for(plane).map_or(&[], |d| (d.wire_format_names)(d))
}

#[cfg(test)]
#[path = "tests/telemetry_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/telemetry_exited_banks_tests.rs"]
mod exited_banks_tests;

pub const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total";

pub const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total";

pub fn upstream_attempt_on(pool_label: &str, lane_label: &str) {
    if !bump_kept(&UNBANKED_ATTEMPTS, pool_label, lane_label) {
        crate::cold::host::telemetry_upstream_attempt_first(pool_label, lane_label);
    }
}

pub fn plugin_label_refused() {
    metrics::counter!(crate::snapshot::PLUGIN_LABEL_REFUSED_TOTAL).increment(1);
}

pub fn upstream_failure_on(pool_label: &str, lane_label: &str, disposition: &'static str) {
    {
        let held = UNBANKED_FAILURES.read().unwrap_or_else(|p| p.into_inner());
        if let Some(counter) = held
            .get(pool_label)
            .and_then(|lanes| lanes.get(lane_label))
            .and_then(|dispositions| dispositions.get(disposition))
        {
            counter.increment(1);
            return;
        }
    }
    crate::cold::host::telemetry_upstream_failure_first(pool_label, lane_label, disposition);
}

pub fn outcome_of(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    }
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub(crate) const COUNTER_CHUNK: usize = 1024;
const COUNTER_CHUNKS: usize = 64;
pub(crate) const HIST_CHUNK: usize = 256;
const HIST_CHUNKS: usize = 32;

/// Histogram slots a table holds (its interning cap).
const HIST_SLOTS: usize = HIST_CHUNK * HIST_CHUNKS;

pub const HIST_DRAIN_THRESHOLD: usize = 65_536;

/// Process-wide bytes of full histogram buffers held for the maintenance thread.
const HIST_PARK_BUDGET_BYTES: usize = 8 * 1024 * 1024;

/// Full buffers the park budget holds (16 at the default threshold).
const HIST_PARK_MAX_BUFFERS: usize =
    HIST_PARK_BUDGET_BYTES / (HIST_DRAIN_THRESHOLD * std::mem::size_of::<f64>());

/// Full buffers one slot may have parked at once; a further one replays on the request thread.
const HIST_PARK_PER_SLOT: usize = 2;

pub(crate) const KEY_SEP: char = '\u{1f}';

pub(crate) const OUTCOMES: [&str; 4] = ["ok", "exhausted", "client_error", "error"];

pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

pub const DISPOSITION_TRANSIENT: &str =
    busbar_contract::upstream::Disposition::TransientUpstream.label();

pub(crate) const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";

pub(crate) const DISPOSITION_HARD_DOWN: &str =
    busbar_contract::upstream::Disposition::HardDown.label();

pub(crate) const DISPOSITIONS: [&str; 4] = [
    DISPOSITION_TRANSIENT,
    DISPOSITION_ATTEMPT_TIMEOUT,
    DISPOSITION_HARD_DOWN,
    busbar_contract::protocol::DISPOSITION_CONTEXT_LENGTH,
];

pub(crate) const REASONS: [&str; 6] = [
    DISPOSITION_TRANSIENT,
    DISPOSITION_ATTEMPT_TIMEOUT,
    DISPOSITION_HARD_DOWN,
    busbar_contract::protocol::DISPOSITION_CONTEXT_LENGTH,
    busbar_kernel_egress::upstream::ERR_NET_CONNECT,
    busbar_kernel_egress::upstream::ERR_NET_TIMEOUT,
];

/// A registered counter cell. `Copy` — the hot path holds and passes these by value. An INVALID
/// slot (registration hit the capacity cap) drops adds; the emit helpers check [`is_valid`] first
/// and fall back to the macro path so no observation is lost.
///
/// [`is_valid`]: CounterSlot::is_valid
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CounterSlot(u32);

/// A registered histogram slot (a per-thread raw-sample buffer, drained at scrape). Same validity
/// contract as [`CounterSlot`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HistogramSlot(u32);

impl CounterSlot {
    pub const INVALID: CounterSlot = CounterSlot(u32::MAX);

    pub fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }

    pub fn add(self, n: u64) {
        if !self.is_valid() {
            return;
        }
        let idx = self.0 as usize;

        let _ = BANK.try_with(|bank| {
            let chunk = bank.counters[idx / COUNTER_CHUNK]
                .get_or_init(crate::cold::host::telemetry_new_counter_chunk);
            let cell = &chunk[idx % COUNTER_CHUNK];
            cell.store(
                cell.load(Ordering::Relaxed).wrapping_add(n),
                Ordering::Relaxed,
            );
        });
    }

    pub fn incr(self) {
        self.add(1);
    }
}

impl HistogramSlot {
    pub const INVALID: HistogramSlot = HistogramSlot(u32::MAX);

    pub fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }

    pub fn record(self, value: f64) {
        self.record_inner(value, crate::snapshot::retaining());
    }

    pub fn record_inner(self, value: f64, retaining: bool) {
        if !self.is_valid() {
            return;
        }
        if !retaining {
            return;
        }
        let idx = self.0 as usize;
        let _ = BANK.try_with(|bank| {
            let chunk = bank.hists[idx / HIST_CHUNK]
                .get_or_init(crate::cold::host::telemetry_new_hist_chunk);
            let mut buf = chunk[idx % HIST_CHUNK]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            buf.push(value);
            if buf.len() >= HIST_DRAIN_THRESHOLD {
                let samples = std::mem::take(&mut *buf);
                drop(buf);
                park_or_replay(self.0, samples);
            }
        });
    }
}

pub(crate) type HistChunk = Box<[Mutex<Vec<f64>>]>;

pub(crate) struct ThreadBank {
    pub(crate) counters: [OnceLock<Box<[AtomicU64]>>; COUNTER_CHUNKS],
    pub(crate) hists: [OnceLock<HistChunk>; HIST_CHUNKS],
}

pub(crate) struct LocalBank(pub(crate) Arc<ThreadBank>);

impl std::ops::Deref for LocalBank {
    type Target = ThreadBank;

    fn deref(&self) -> &ThreadBank {
        &self.0
    }
}

impl ThreadBank {
    fn new() -> Self {
        ThreadBank {
            counters: std::array::from_fn(|_| OnceLock::new()),
            hists: std::array::from_fn(|_| OnceLock::new()),
        }
    }
}

thread_local! {
    /// This thread's bank. Created on first emission; the registry keeps a second `Arc` so the
    /// aggregator can read a dead thread's final totals (counters are cumulative — dropping a dead
    /// thread's cells unread would make the exposed totals REGRESS, which Prometheus rejects).
    ///
    /// A bank whose thread has exited is RELEASED at the next flush, not kept: its counters are
    /// folded into each slot's `retired` base and its histogram buffers drained, and then the
    /// registry lets go. Tokio reaps idle blocking threads and spawns fresh ones on the
    /// next burst, and banked emission is reachable from them (`translation`, via a cross-protocol
    /// body large enough to be offloaded) — a registry that only grew kept one bank per thread that
    /// ever emitted, for the process's life, and walked every one of them on every flush.
    static BANK: LocalBank = {
        let bank = Arc::new(ThreadBank::new());
        registry()
            .threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(bank_key(&bank), bank.clone());
        LocalBank(bank)
    };
}

pub(crate) struct SlotDesc<H> {
    pub(crate) name: &'static str,
    pub(crate) labels: Vec<(&'static str, String)>,

    pub(crate) handle: OnceLock<H>,

    pub(crate) flushed: AtomicU64,

    pub(crate) retired: AtomicU64,
}

pub(crate) struct SlotTable<H> {
    pub(crate) index: Mutex<HashMap<String, u32>>,
    pub(crate) descs: RwLock<Vec<Arc<SlotDesc<H>>>>,
}

impl<H> SlotTable<H> {
    fn new() -> Self {
        SlotTable {
            index: Mutex::new(HashMap::default()),
            descs: RwLock::new(Vec::new()),
        }
    }
}

pub(crate) struct Registry {
    pub(crate) counters: SlotTable<metrics::Counter>,
    pub(crate) hists: SlotTable<metrics::Histogram>,
    /// Every registered bank, keyed by its allocation address ([`bank_key`]).
    pub(crate) threads: Mutex<foldhash::HashMap<usize, Arc<ThreadBank>>>,
    /// Banks whose thread has exited while the recorder retains them: the next flush folds and
    /// releases exactly these, in O(exited), instead of scanning every registered bank.
    pub(crate) exited: Mutex<Vec<Arc<ThreadBank>>>,

    pub(crate) flush_lock: Mutex<()>,
}

pub(crate) fn bank_key(bank: &Arc<ThreadBank>) -> usize {
    Arc::as_ptr(bank) as usize
}

pub(crate) fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        counters: SlotTable::new(),
        hists: SlotTable::new(),
        threads: Mutex::new(foldhash::HashMap::default()),
        exited: Mutex::new(Vec::new()),
        flush_lock: Mutex::new(()),
    })
}

pub fn counter_slot(name: &'static str, labels: &[(&'static str, &str)]) -> CounterSlot {
    match registry()
        .counters
        .intern(name, labels, COUNTER_CHUNK * COUNTER_CHUNKS)
    {
        Some(id) => CounterSlot(id),
        None => CounterSlot::INVALID,
    }
}

pub fn histogram_slot(name: &'static str, labels: &[(&'static str, &str)]) -> HistogramSlot {
    match registry().hists.intern(name, labels, HIST_SLOTS) {
        Some(id) => HistogramSlot(id),
        None => HistogramSlot::INVALID,
    }
}

/// Full histogram buffers waiting for the maintenance thread's next flush.
pub(crate) struct Parked {
    /// The parked buffers, as `(slot, samples)`. Bounded by [`HIST_PARK_MAX_BUFFERS`] overall and
    /// [`HIST_PARK_PER_SLOT`] per slot.
    pub(crate) buffers: Vec<(u32, Vec<f64>)>,
    /// Per histogram slot, how many of `buffers` are its own; kept with every park and zeroed when
    /// the flush takes the buffers.
    pub(crate) per_slot: [u8; HIST_SLOTS],
}

pub(crate) static HIST_PARKED: Mutex<Parked> = Mutex::new(Parked {
    buffers: Vec::new(),
    per_slot: [0; HIST_SLOTS],
});

/// A full buffer leaves the request thread without touching the recorder: it is parked for the
/// maintenance thread's flush. Only when the slot already has its share parked, or the process-wide
/// park budget is spent, is it replayed inline, and that replay is counted.
fn park_or_replay(slot: u32, samples: Vec<f64>) {
    if !crate::snapshot::recorder_installed() {
        return;
    }
    let samples = {
        let mut parked = HIST_PARKED.lock().unwrap_or_else(|p| p.into_inner());
        let Parked { buffers, per_slot } = &mut *parked;
        if let Some(mine) = per_slot.get_mut(slot as usize) {
            if buffers.len() < HIST_PARK_MAX_BUFFERS && usize::from(*mine) < HIST_PARK_PER_SLOT {
                *mine += 1;
                buffers.push((slot, samples));
                return;
            }
        }
        samples
    };
    metrics::counter!(crate::snapshot::TELEMETRY_OVERFLOW_REPLAYS_TOTAL).increment(1);
    drain_hist_overflow(slot, samples);
}

fn drain_hist_overflow(slot: u32, samples: Vec<f64>) {
    if !crate::snapshot::recorder_installed() {
        return;
    }
    let desc = {
        let descs = registry()
            .hists
            .descs
            .read()
            .unwrap_or_else(|p| p.into_inner());
        match descs.get(slot as usize) {
            Some(d) => d.clone(),
            None => return,
        }
    };
    let handle = desc
        .handle
        .get_or_init(|| crate::off_path::telemetry::mint_histogram(&desc));
    #[cfg(test)]
    bank_internals::REQUEST_THREAD_RECORDS.with(|n| n.set(n.get() + samples.len() as u64));
    for s in samples {
        handle.record(s);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod drain_serial {
    use std::cell::Cell;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    thread_local! {
        /// 0 = this thread does not hold `LOCK`; 1 = it does (nesting is strictly re-entrant, so a
        /// boolean depth suffices).
        static HELD: Cell<bool> = const { Cell::new(false) };
    }

    pub struct Guard(Option<MutexGuard<'static, ()>>);

    impl Drop for Guard {
        fn drop(&mut self) {
            if self.0.is_some() {
                HELD.with(|h| h.set(false));
            }
        }
    }

    pub fn lock() -> Guard {
        if HELD.with(Cell::get) {
            return Guard(None);
        }
        let g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        HELD.with(|h| h.set(true));
        Guard(Some(g))
    }
}

pub fn flush_to_recorder() {
    crate::off_path::telemetry::flush_to_recorder();
}

#[cfg(test)]
pub(crate) fn this_threads_bank() -> std::sync::Weak<dyn std::any::Any + Send + Sync> {
    BANK.with(|bank| {
        let bank: Arc<dyn std::any::Any + Send + Sync> = bank.0.clone();
        Arc::downgrade(&bank)
    })
}

#[cfg(test)]
#[path = "tests/telemetry_bank_internals_tests.rs"]
pub mod bank_internals;
