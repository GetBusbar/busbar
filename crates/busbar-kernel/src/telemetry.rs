// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::state::App;

/// The banked slots for one request family: `busbar_requests_total` (per outcome) and
/// `busbar_request_duration_seconds`, for a fixed `(ingress_protocol, pool)` pair ON THE PLANE THIS
/// BANK REGISTERS (see [`AppSlots::build`]).
#[derive(Clone, Copy)]
struct RequestFamily {
    requests: [CounterSlot; OUTCOMES.len()],
    duration: HistogramSlot,
}

/// The banked slots for one `(pool label, lane)` pair on the upstream walk:
/// attempts, per-disposition failures, and breaker trips.
#[derive(Clone, Copy)]
struct LaneFamily {
    attempts: CounterSlot,
    failures: [CounterSlot; DISPOSITIONS.len()],
    trips: CounterSlot,
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
    banked_plane: &'static str,
    /// pool label (ingress convention: pools ∪ models ∪ "unresolved") → per-dialect request
    /// families, indexed by position in the banked plane's declared dialects
    /// ([`declared_dialects`]).
    request: HashMap<Box<str>, Box<[RequestFamily]>>,
    /// engine pool label (pools ∪ models, matching `proxy::metric_pool_label`) → lane idx → family.
    lane: HashMap<Box<str>, HashMap<usize, LaneFamily>>,
    /// engine pool label → failover-reason slots, indexed by position in [`REASONS`].
    failover: HashMap<Box<str>, [CounterSlot; REASONS.len()]>,
}

impl AppSlots {
    pub(crate) fn build<'a>(
        pools: &[(&'a str, Vec<usize>)],
        by_model: &[(&'a str, usize)],
        lane_model: impl Fn(usize) -> Option<&'a str>,
        plane: &'static str,
    ) -> AppSlots {
        use crate::snapshot::{
            BREAKER_TRIPS_TOTAL, FAILOVERS_TOTAL, REQUESTS_TOTAL, REQUEST_DURATION_SECONDS,
            UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL,
        };

        let mut ingress_labels: Vec<&str> = pools.iter().map(|(pool, _)| *pool).collect();
        ingress_labels.extend(by_model.iter().map(|(model, _)| *model));
        ingress_labels.push(POOL_LABEL_UNRESOLVED);
        ingress_labels.sort_unstable();
        ingress_labels.dedup();

        let mut request = HashMap::with_capacity(ingress_labels.len());
        for pool in &ingress_labels {
            let families: Box<[RequestFamily]> = declared_dialects(plane)
                .iter()
                .map(|proto| RequestFamily {
                    requests: std::array::from_fn(|oi| {
                        counter_slot(
                            REQUESTS_TOTAL,
                            &[
                                ("ingress_protocol", proto),
                                ("pool", pool),
                                ("outcome", OUTCOMES[oi]),
                            ],
                        )
                    }),
                    duration: histogram_slot(
                        REQUEST_DURATION_SECONDS,
                        &[("ingress_protocol", proto), ("pool", pool)],
                    ),
                })
                .collect();
            request.insert(Box::from(*pool), families);
        }

        let mut lane_map: HashMap<Box<str>, HashMap<usize, LaneFamily>> = HashMap::new();
        let engine_labels: Vec<(&str, Vec<usize>)> = pools
            .iter()
            .map(|(pool, member_idxs)| (*pool, member_idxs.clone()))
            .chain(by_model.iter().map(|(model, idx)| (*model, vec![*idx])))
            .collect();

        let mut failover = HashMap::with_capacity(engine_labels.len());
        for (pool, member_idxs) in &engine_labels {
            let mut per_lane = HashMap::with_capacity(member_idxs.len());
            for &idx in member_idxs {
                let Some(lane_label) = lane_model(idx) else {
                    continue;
                };
                per_lane.insert(
                    idx,
                    LaneFamily {
                        attempts: counter_slot(
                            UPSTREAM_ATTEMPTS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                        failures: std::array::from_fn(|di| {
                            counter_slot(
                                UPSTREAM_FAILURES_TOTAL,
                                &[
                                    ("pool", pool),
                                    ("lane", lane_label),
                                    ("disposition", DISPOSITIONS[di]),
                                ],
                            )
                        }),
                        trips: counter_slot(
                            BREAKER_TRIPS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                    },
                );
            }
            lane_map
                .entry(Box::from(*pool))
                .or_default()
                .extend(per_lane);
            failover.entry(Box::from(*pool)).or_insert_with(|| {
                std::array::from_fn(|ri| {
                    counter_slot(FAILOVERS_TOTAL, &[("pool", pool), ("reason", REASONS[ri])])
                })
            });
        }

        AppSlots {
            banked_plane: plane,
            request,
            lane: lane_map,
            failover,
        }
    }

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

    fn lane_family(&self, pool_label: &str, lane_idx: usize) -> Option<&LaneFamily> {
        self.lane.get(pool_label)?.get(&lane_idx)
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
    if !crate::plane_driver::dispatch::is_fallback(plane) {
        crate::snapshot::incr_plane_requests_total(plane, ingress_protocol, pool, outcome);
        crate::snapshot::record_plane_request_duration(plane, ingress_protocol, pool, seconds);
        return;
    }

    let fam = slots.request_family(plane, ingress_protocol, pool);
    let outcome_idx = OUTCOMES.iter().position(|o| *o == outcome);
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
) {
    let outcome = model_request_finished_in(&app.tslots, ingress_protocol, pool, status, seconds);

    if app
        .export_projections
        .wants_stream(busbar_contract::abi::export::ExportStream::Logs)
    {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        crate::export::deliver_request_log(&crate::export::RequestLogFacts {
            ts: busbar_kernel::store::now(),
            ingress_protocol,
            pool,
            outcome,
            latency_ms: (seconds * 1000.0) as u64,
        });
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

pub fn breaker_trip_on(pool_label: &str, lane_label: &str) {
    metrics::counter!(
        crate::snapshot::BREAKER_TRIPS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    )
    .increment(1);
}

pub fn failover_on(pool_label: &str, reason: &'static str) {
    metrics::counter!(
        crate::snapshot::FAILOVERS_TOTAL,
        "pool" => pool_label.to_owned(),
        "reason" => reason
    )
    .increment(1);
}

pub fn pool_queued_on(pool_label: &str, depth: i64) {
    metrics::gauge!(crate::snapshot::POOL_QUEUED, "pool" => pool_label.to_owned())
        .set(depth as f64);
}

pub fn translation(from: &str, to: &str) {
    static SLOTS: OnceLock<Vec<(&'static str, &'static str, CounterSlot)>> = OnceLock::new();
    let table = SLOTS.get_or_init(|| {
        let mut v = Vec::new();
        let dialects = declared_dialects(crate::plane_driver::dispatch::fallback_key());
        for f in dialects {
            for t in dialects {
                if f != t {
                    v.push((
                        *f,
                        *t,
                        counter_slot(
                            crate::snapshot::TRANSLATIONS_TOTAL,
                            &[("from", f), ("to", t)],
                        ),
                    ));
                }
            }
        }
        v
    });
    match table
        .iter()
        .find(|(f, t, slot)| *f == from && *t == to && slot.is_valid())
    {
        Some((_, _, slot)) => slot.incr(),
        None => metrics::counter!(
            crate::snapshot::TRANSLATIONS_TOTAL,
            "from" => from.to_string(),
            "to" => to.to_string()
        )
        .increment(1),
    }
}

fn declared_dialects(plane: &str) -> &'static [&'static str] {
    crate::plane_driver::registry::plane_decl_for(plane).map_or(&[], |d| (d.wire_format_names)(d))
}

#[cfg(test)]
#[path = "tests/telemetry_tests.rs"]
mod tests;

pub const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total";

pub const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total";

pub fn upstream_attempt_on(pool_label: &str, lane_label: &str) {
    metrics::counter!(
        UPSTREAM_ATTEMPTS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    )
    .increment(1);
}

pub fn plugin_label_refused() {
    metrics::counter!(crate::snapshot::PLUGIN_LABEL_REFUSED_TOTAL).increment(1);
}

pub fn upstream_failure_on(pool_label: &str, lane_label: &str, disposition: &'static str) {
    metrics::counter!(
        UPSTREAM_FAILURES_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned(),
        "disposition" => disposition
    )
    .increment(1);
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

use crate::diag_warn;
use crate::diagnostics::TELEMETRY_SLOT_TABLE_FULL;

const COUNTER_CHUNK: usize = 1024;
const COUNTER_CHUNKS: usize = 64;
const HIST_CHUNK: usize = 256;
const HIST_CHUNKS: usize = 32;

pub const HIST_DRAIN_THRESHOLD: usize = 65_536;

const KEY_SEP: char = '\u{1f}';

pub const OUTCOMES: [&str; 4] = ["ok", "exhausted", "client_error", "error"];

pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

pub const DISPOSITION_TRANSIENT: &str =
    busbar_contract::upstream::Disposition::TransientUpstream.label();

pub const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";

pub const DISPOSITION_HARD_DOWN: &str = busbar_contract::upstream::Disposition::HardDown.label();

pub const DISPOSITIONS: [&str; 4] = [
    DISPOSITION_TRANSIENT,
    DISPOSITION_ATTEMPT_TIMEOUT,
    DISPOSITION_HARD_DOWN,
    busbar_contract::protocol::DISPOSITION_CONTEXT_LENGTH,
];

pub const REASONS: [&str; 6] = [
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
            let chunk = bank.counters[idx / COUNTER_CHUNK].get_or_init(new_counter_chunk);
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
            let chunk = bank.hists[idx / HIST_CHUNK].get_or_init(new_hist_chunk);
            let mut buf = chunk[idx % HIST_CHUNK]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            buf.push(value);
            if buf.len() >= HIST_DRAIN_THRESHOLD {
                let samples = std::mem::take(&mut *buf);
                drop(buf);
                drain_hist_overflow(self.0, samples);
            }
        });
    }
}

type HistChunk = Box<[Mutex<Vec<f64>>]>;

struct ThreadBank {
    counters: [OnceLock<Box<[AtomicU64]>>; COUNTER_CHUNKS],
    hists: [OnceLock<HistChunk>; HIST_CHUNKS],
}

struct LocalBank(Arc<ThreadBank>);

impl std::ops::Deref for LocalBank {
    type Target = ThreadBank;

    fn deref(&self) -> &ThreadBank {
        &self.0
    }
}

impl Drop for LocalBank {
    fn drop(&mut self) {
        if crate::snapshot::retaining() {
            return;
        }

        let reg = registry();
        let _flush = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());
        reg.threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|bank| !Arc::ptr_eq(bank, &self.0));
        let descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
        for (i, desc) in descs.iter().enumerate() {
            if let Some(chunk) = self.counters[i / COUNTER_CHUNK].get() {
                desc.retired.fetch_add(
                    chunk[i % COUNTER_CHUNK].load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
            }
        }
    }
}

fn new_counter_chunk() -> Box<[AtomicU64]> {
    (0..COUNTER_CHUNK).map(|_| AtomicU64::new(0)).collect()
}

fn new_hist_chunk() -> HistChunk {
    (0..HIST_CHUNK).map(|_| Mutex::new(Vec::new())).collect()
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
    /// registry lets go (item 567). Tokio reaps idle blocking threads and spawns fresh ones on the
    /// next burst, and banked emission is reachable from them (`translation`, via a cross-protocol
    /// body large enough to be offloaded) — a registry that only grew kept one bank per thread that
    /// ever emitted, for the process's life, and walked every one of them on every flush.
    static BANK: LocalBank = {
        let bank = Arc::new(ThreadBank::new());
        registry()
            .threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(bank.clone());
        LocalBank(bank)
    };
}

struct SlotDesc<H> {
    name: &'static str,
    labels: Vec<(&'static str, String)>,

    handle: OnceLock<H>,

    flushed: AtomicU64,

    retired: AtomicU64,
}

struct SlotTable<H> {
    index: Mutex<HashMap<String, u32>>,
    descs: RwLock<Vec<Arc<SlotDesc<H>>>>,
}

impl<H> SlotTable<H> {
    fn new() -> Self {
        SlotTable {
            index: Mutex::new(HashMap::new()),
            descs: RwLock::new(Vec::new()),
        }
    }

    fn intern(
        &self,
        name: &'static str,
        labels: &[(&'static str, &str)],
        max: usize,
    ) -> Option<u32> {
        let mut key = String::with_capacity(name.len() + labels.len() * 16);
        key.push_str(name);
        for (k, v) in labels {
            key.push(KEY_SEP);
            key.push_str(k);
            key.push(KEY_SEP);
            key.push_str(v);
        }
        let mut index = self.index.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(&id) = index.get(key.as_str()) {
            return Some(id);
        }
        let mut descs = self.descs.write().unwrap_or_else(|p| p.into_inner());
        if descs.len() >= max {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                diag_warn!(
                    TELEMETRY_SLOT_TABLE_FULL,
                    metric = name,
                    cap = max,
                    "telemetry bank slot table full; further label sets fall back to the metrics macros"
                );
            }
            return None;
        }
        let id = descs.len() as u32;
        descs.push(Arc::new(SlotDesc {
            name,
            labels: labels.iter().map(|(k, v)| (*k, (*v).to_string())).collect(),
            handle: OnceLock::new(),
            flushed: AtomicU64::new(0),
            retired: AtomicU64::new(0),
        }));
        index.insert(key, id);
        Some(id)
    }
}

struct Registry {
    counters: SlotTable<metrics::Counter>,
    hists: SlotTable<metrics::Histogram>,
    threads: Mutex<Vec<Arc<ThreadBank>>>,

    flush_lock: Mutex<()>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        counters: SlotTable::new(),
        hists: SlotTable::new(),
        threads: Mutex::new(Vec::new()),
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
    match registry()
        .hists
        .intern(name, labels, HIST_CHUNK * HIST_CHUNKS)
    {
        Some(id) => HistogramSlot(id),
        None => HistogramSlot::INVALID,
    }
}

static METADATA: metrics::Metadata<'static> =
    metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!()));

fn key_of<H>(desc: &SlotDesc<H>) -> metrics::Key {
    let labels = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()));
    metrics::Key::from_parts(desc.name, labels.collect::<Vec<_>>())
}

fn mint_counter(desc: &SlotDesc<metrics::Counter>) -> metrics::Counter {
    metrics::with_recorder(|r| r.register_counter(&key_of(desc), &METADATA))
}

fn mint_histogram(desc: &SlotDesc<metrics::Histogram>) -> metrics::Histogram {
    metrics::with_recorder(|r| r.register_histogram(&key_of(desc), &METADATA))
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
    let handle = desc.handle.get_or_init(|| mint_histogram(&desc));
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
    #[cfg(any(test, feature = "test-support"))]
    let _serial = drain_serial::lock();
    if !crate::snapshot::recorder_installed() {
        return;
    }
    let reg = registry();
    let _guard = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());

    let mut banks = reg.threads.lock().unwrap_or_else(|p| p.into_inner());
    let exited: Vec<_> = banks
        .extract_if(.., |b| Arc::strong_count(b) == 1)
        .collect();
    let threads = banks.clone();
    drop(banks);
    std::sync::atomic::fence(Ordering::Acquire);

    let counter_descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in counter_descs.iter().enumerate() {
        let (chunk_i, off) = (i / COUNTER_CHUNK, i % COUNTER_CHUNK);
        let mut sum: u64 = desc.retired.load(Ordering::Relaxed);
        for bank in threads.iter().chain(&exited) {
            if let Some(chunk) = bank.counters[chunk_i].get() {
                sum = sum.wrapping_add(chunk[off].load(Ordering::Relaxed));
            }
        }

        let gone = exited.iter().filter_map(|b| b.counters[chunk_i].get());
        let gone = gone.fold(0u64, |t, c| t.wrapping_add(c[off].load(Ordering::Relaxed)));
        desc.retired.fetch_add(gone, Ordering::Relaxed);
        let prev = desc.flushed.load(Ordering::Relaxed);
        if sum > prev {
            let handle = desc.handle.get_or_init(|| mint_counter(desc));
            handle.increment(sum - prev);
            desc.flushed.store(sum, Ordering::Relaxed);
        }
    }
    drop(counter_descs);

    let hist_descs = reg.hists.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in hist_descs.iter().enumerate() {
        let (chunk_i, off) = (i / HIST_CHUNK, i % HIST_CHUNK);
        for bank in threads.iter().chain(&exited) {
            let Some(chunk) = bank.hists[chunk_i].get() else {
                continue;
            };
            let samples = {
                let mut buf = chunk[off].lock().unwrap_or_else(|p| p.into_inner());
                if buf.is_empty() {
                    continue;
                }
                std::mem::take(&mut *buf)
            };
            let handle = desc.handle.get_or_init(|| mint_histogram(desc));
            for s in samples {
                handle.record(s);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn this_threads_bank() -> std::sync::Weak<dyn std::any::Any + Send + Sync> {
    BANK.with(|bank| {
        let bank: Arc<dyn std::any::Any + Send + Sync> = bank.0.clone();
        Arc::downgrade(&bank)
    })
}

#[cfg(test)]
pub mod bank_internals {
    pub use super::HIST_DRAIN_THRESHOLD;

    pub fn hist_chunk_materialized(slot: super::HistogramSlot) -> bool {
        let idx = slot.0 as usize;
        super::BANK.with(|bank| bank.hists[idx / super::HIST_CHUNK].get().is_some())
    }
}
