// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOSTLESS UPSTREAM-COUNT EMITS, in the neutral substrate.
//!
//! `upstream_attempt_on` / `upstream_failure_on` are the two `(pool, lane)`-labelled counters every
//! plane's synchronous client leg emits for the upstream calls busbar itself originates. They take
//! NO `App` — both labels are operator-configured (a registration id and a transport/binding word off
//! a closed axis), never caller-supplied, so the series count stays bounded without an engine handle.
//! That makes the emit itself a pure `metrics` write, which is why it lives here: a plane names it
//! (`busbar_substrate::telemetry::upstream_attempt_on`) without reaching into `busbar-core`, and
//! core's `crate::telemetry` re-exports both so its own `App`-holding wrappers call them unchanged.

/// `busbar_upstream_attempts_total` — labels: pool (bounded), lane.
pub const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total";
/// `busbar_upstream_failures_total` — labels: pool (bounded), lane, disposition.
pub const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total";

/// `busbar_upstream_attempts_total` for one dispatch attempt on `(pool label, lane label)`.
///
/// BOTH LABELS ARE OPERATOR-CONFIGURED and therefore bounded: the pool label is a registration name
/// out of the operator's config and the lane label is a transport/binding word off a closed axis.
/// Neither is caller-supplied, so a client-supplied value here could never mint a time series per
/// distinct string.
pub fn upstream_attempt_on(pool_label: &str, lane_label: &str) {
    metrics::counter!(
        UPSTREAM_ATTEMPTS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    )
    .increment(1);
}

/// `busbar_upstream_failures_total` for one classified failure on `(pool label, lane label)`.
///
/// THE EMIT for this family, on EVERY plane — see [`upstream_attempt_on`] for why there is no `&App`
/// and why both labels are bounded. `disposition` is the model plane's own vocabulary (the
/// `DISPOSITION_*` values in [`crate::proxy`]) and no plane gets one of its own.
pub fn upstream_failure_on(pool_label: &str, lane_label: &str, disposition: &'static str) {
    metrics::counter!(
        UPSTREAM_FAILURES_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned(),
        "disposition" => disposition
    )
    .increment(1);
}

/// THE HTTP STATUS → OUTCOME LABEL, in the neutral substrate. A pure `u16 → &'static str` fold over a
/// CLOSED set of outcome words (`ok`, `exhausted`, `client_error`, `error`) — no `App`, no state — so
/// every plane names it (`busbar_substrate::telemetry::outcome_of`) for its own request-completion
/// label without reaching into `busbar-core`, and core's `crate::telemetry` re-exports it so its own
/// call sites are unchanged. `503` is called out as `exhausted` (a pool ran dry) distinctly from the
/// rest of the `5xx`/other band, exactly as before.
pub fn outcome_of(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    }
}

// ── THE TELEMETRY BANK (relocated from busbar-core, verbatim) ────────────────────────────────────
//
// Per-thread metric cells for the request hot path plus the one scrape-time aggregator that folds
// them into the process-global recorder. The bank names NO `App`: a slot is interned from a metric
// name and a bounded label set, the per-thread storage is chunked `AtomicU64`/`Vec<f64>`, and the
// flush talks only to the `metrics` facade — so it belongs beside the recorder install it feeds
// (`crate::metrics`), not beside the `App`-shaped emit wrappers that call into it. Core's
// `crate::telemetry` re-exports every item below at its historical path, so every existing core call
// site resolves unchanged and the exposition it produces is byte-identical.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::diag_warn;
use crate::diagnostics::TELEMETRY_SLOT_TABLE_FULL;

// ── Capacity ─────────────────────────────────────────────────────────────────────────────────────
//
// Slots are process-lifetime (the intern table is append-only; identical label sets re-registered by
// a later config generation reuse their slot). Per-thread storage is CHUNKED and lazily allocated:
// a thread only materializes the 8 KiB counter chunk / sample-buffer chunk that one of its slots
// actually lands in, so a mostly-idle thread costs almost nothing. The caps below are far beyond any
// real deployment (a pool contributes ~40 counter slots + ~6 histogram slots); if the table ever
// fills — e.g. a pathological test suite churning thousands of distinct pool names — registration
// degrades gracefully: it returns an INVALID slot and the emit helpers fall back to the macros.
const COUNTER_CHUNK: usize = 1024;
const COUNTER_CHUNKS: usize = 64; // 65,536 counter slots
const HIST_CHUNK: usize = 256;
const HIST_CHUNKS: usize = 32; // 8,192 histogram slots
/// A per-thread histogram buffer that grows past this many samples between scrapes drains straight
/// into the recorder (the old contended path) rather than growing without bound — correctness is
/// preserved and the cost is amortized 1/N. Only reachable when scrapes stop while traffic doesn't.
pub const HIST_DRAIN_THRESHOLD: usize = 65_536;

/// Joins label values into the intern key — a control byte that cannot occur in a metric name,
/// label key, or any of the (operator-bounded) label values, so the join is unambiguous.
const KEY_SEP: char = '\u{1f}';

// ── Fixed label vocabularies (indices into the per-family slot arrays) ──────────────────────────

/// `outcome` values on `busbar_requests_total`. The classification itself is [`outcome_of`], which
/// is the ONLY thing that produces one of these — see there for why it is a function.
pub const OUTCOMES: [&str; 4] = ["ok", "exhausted", "client_error", "error"];

/// `disposition` values on `busbar_upstream_failures_total` (see `proxy::DISPOSITION_*`).
pub const DISPOSITIONS: [&str; 4] = [
    crate::proxy::DISPOSITION_TRANSIENT,
    crate::proxy::DISPOSITION_ATTEMPT_TIMEOUT,
    crate::proxy::DISPOSITION_HARD_DOWN,
    crate::proxy::DISPOSITION_CONTEXT_LENGTH,
];
/// `reason` values on `busbar_failovers_total`: the dispositions plus the transport error classes
/// the pre-response failure arm records (`proxy::ERR_NET_CONNECT` / `ERR_NET_TIMEOUT`).
pub const REASONS: [&str; 6] = [
    crate::proxy::DISPOSITION_TRANSIENT,
    crate::proxy::DISPOSITION_ATTEMPT_TIMEOUT,
    crate::proxy::DISPOSITION_HARD_DOWN,
    crate::proxy::DISPOSITION_CONTEXT_LENGTH,
    crate::proxy::ERR_NET_CONNECT,
    crate::proxy::ERR_NET_TIMEOUT,
];

// ── Slot handles ─────────────────────────────────────────────────────────────────────────────────

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

    /// Owner-writes-only add into THIS thread's cell. Relaxed load+store (not `fetch_add`) is
    /// sufficient and cheapest: the owning thread is the only writer, the atomic type only makes the
    /// aggregator's concurrent reads defined. No-op for INVALID slots and during TLS teardown.
    ///
    /// DELIBERATELY unconditional even when metrics are off — unlike `HistogramSlot::record`, this
    /// does NOT gate on `metrics::retaining()`. Counters are cumulative: an add from before the
    /// recorder installs must still be reflected in the post-install total, so it cannot simply be
    /// dropped the way an off-metrics histogram sample can. And unlike a histogram's raw-sample
    /// buffer, a counter cell's footprint is bounded by thread count x chunk count, not by traffic
    /// volume — an idle process's counters cost the same few bytes whether metrics are on or off, so
    /// there is no unbounded-retention problem here to fix. (This is why `configure`'s doc comment
    /// says "nothing UNBOUNDED is retained" rather than a literal "nothing is retained".)
    pub fn add(self, n: u64) {
        if !self.is_valid() {
            return;
        }
        let idx = self.0 as usize;
        // `try_with`: an emission from a destructor after the thread's bank was torn down is
        // dropped rather than panicking — the bank is observation-only (THE RULE), so a lost
        // observation on thread death is acceptable where a panic is not.
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

    /// Buffer one observation in THIS thread's sample vector — but ONLY if something will ever
    /// drain it. See [`Self::record_inner`] for the gating rationale; this wrapper just supplies
    /// the live decision from `metrics::retaining()`.
    pub fn record(self, value: f64) {
        self.record_inner(value, crate::metrics::retaining());
    }

    /// `retaining` is passed in explicitly (rather than read here) so this is testable without
    /// process-global `OnceLock` state: `metrics::HANDLE`/`ENABLED` can only be set once per
    /// process, so a test can't reset them to exercise every branch — it can, however, call this
    /// directly with a hand-picked `retaining`.
    ///
    /// When `retaining` is `false` (metrics off, or the recorder never installed / failed to
    /// install), the sample is dropped immediately and the per-thread `HistChunk` for this slot is
    /// never even materialized — nothing here will ever be drained (not by a scrape, not by the
    /// `HIST_DRAIN_THRESHOLD` overflow backstop, not by anything else), so buffering it would only
    /// grow memory with traffic volume for no eventual consumer. This is checked BEFORE the
    /// `BANK`/`try_with` TLS access precisely so an off-metrics process never allocates a histogram
    /// buffer it will never use.
    ///
    /// KNOWN RESIDUAL: if recorder install FAILS after the boot-window traffic already buffered
    /// some samples (see `metrics::retaining`'s doc comment for that window), those already-buffered
    /// samples are not proactively freed here — they sit until `HIST_DRAIN_THRESHOLD` or thread
    /// exit reclaims them. Bounded by one ~200 ms window's traffic, and the install failure itself
    /// is already logged (`tracing::error!` in `metrics::init_with`), so the cause is discoverable.
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
                // Scrapes have stopped but traffic hasn't: drain through the recorder inline
                // (bounded memory beats bank locality when nobody is scraping).
                let samples = std::mem::take(&mut *buf);
                drop(buf);
                drain_hist_overflow(self.0, samples);
            }
        });
    }
}

// ── Per-thread bank ──────────────────────────────────────────────────────────────────────────────

/// One lazily-allocated block of per-thread histogram sample buffers (see `ThreadBank::hists`).
type HistChunk = Box<[Mutex<Vec<f64>>]>;

struct ThreadBank {
    counters: [OnceLock<Box<[AtomicU64]>>; COUNTER_CHUNKS],
    hists: [OnceLock<HistChunk>; HIST_CHUNKS],
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
    /// aggregator can keep summing a dead thread's final totals (counters are cumulative — dropping
    /// a dead thread's cells would make the exposed totals REGRESS, which Prometheus rejects).
    static BANK: Arc<ThreadBank> = {
        let bank = Arc::new(ThreadBank::new());
        registry()
            .threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(bank.clone());
        bank
    };
}

// ── Global registry (intern table + thread list + aggregator state) ─────────────────────────────

struct SlotDesc<H> {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    /// The recorder handle, minted LAZILY at first flush — never before the recorder is installed
    /// (a handle minted against the pre-install no-op recorder would be bound to it forever).
    handle: OnceLock<H>,
    /// Counters only: the total already pushed into the recorder. Guarded by `flush_lock` (single
    /// writer); atomic so the cold-path reader needs no lock.
    flushed: AtomicU64,
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

    /// Intern `(name, labels)` → slot id. Identical label sets always resolve to the SAME slot, so
    /// re-registration across config generations accumulates into the same cells. Returns `None`
    /// at the capacity cap (`max`), after which callers degrade to the macro path.
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
            // Warn once per table, not per registration — the fallback path is correct, just slower.
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
        }));
        index.insert(key, id);
        Some(id)
    }
}

struct Registry {
    counters: SlotTable<metrics::Counter>,
    hists: SlotTable<metrics::Histogram>,
    threads: Mutex<Vec<Arc<ThreadBank>>>,
    /// Serializes flushes so the read-sum / delta-increment / store-flushed sequence is atomic per
    /// slot (two concurrent scrapes must not double-count a delta).
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

/// Register (or re-resolve) a counter slot for a bounded label set. Registration-time only — the
/// hot path holds the returned slot. Label VALUES must come from operator-bounded vocabularies
/// (the same cardinality contract as `metrics.rs`).
pub fn counter_slot(name: &'static str, labels: &[(&'static str, &str)]) -> CounterSlot {
    match registry()
        .counters
        .intern(name, labels, COUNTER_CHUNK * COUNTER_CHUNKS)
    {
        Some(id) => CounterSlot(id),
        None => CounterSlot::INVALID,
    }
}

/// Register (or re-resolve) a histogram slot. Same contract as [`counter_slot`].
pub fn histogram_slot(name: &'static str, labels: &[(&'static str, &str)]) -> HistogramSlot {
    match registry()
        .hists
        .intern(name, labels, HIST_CHUNK * HIST_CHUNKS)
    {
        Some(id) => HistogramSlot(id),
        None => HistogramSlot::INVALID,
    }
}

// ── Aggregator ───────────────────────────────────────────────────────────────────────────────────

/// Metric metadata for handles minted outside the `metrics` macros (the macros bake an equivalent
/// static). Target/module only affect recorder-side filtering, which the Prometheus exporter
/// ignores, so one shared value serves every slot.
static METADATA: metrics::Metadata<'static> =
    metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!()));

fn mint_counter(desc: &SlotDesc<metrics::Counter>) -> metrics::Counter {
    let labels: Vec<metrics::Label> = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()))
        .collect();
    let key = metrics::Key::from_parts(desc.name, labels);
    metrics::with_recorder(|r| r.register_counter(&key, &METADATA))
}

fn mint_histogram(desc: &SlotDesc<metrics::Histogram>) -> metrics::Histogram {
    let labels: Vec<metrics::Label> = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()))
        .collect();
    let key = metrics::Key::from_parts(desc.name, labels);
    metrics::with_recorder(|r| r.register_histogram(&key, &METADATA))
}

/// Overflow drain for a histogram buffer that outgrew [`HIST_DRAIN_THRESHOLD`]: push the samples
/// through the recorder handle directly. Pre-install the recorder is a no-op sink (matching the
/// macro behavior in the same situation), so the samples are dropped rather than hoarded.
fn drain_hist_overflow(slot: u32, samples: Vec<f64>) {
    if !crate::metrics::recorder_installed() {
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

/// TEST-ONLY drain serialisation — a MEASUREMENT guard, not a correctness one.
///
/// [`flush_to_recorder`] MOVES each thread's sample `Vec` out (`mem::take`) and DROPS it on the
/// DRAINING thread, so the free is charged to whoever drains rather than to the thread that
/// allocated the buffer. `test_observations_are_released_after_the_load_stops` reads per-THREAD
/// jemalloc alloc/dealloc counters exactly so its measurement is immune to the rest of the suite —
/// but that immunity does NOT survive another test draining ITS buffer: those frees land on the
/// other thread and leave `allocated - deallocated` on the measuring thread permanently inflated.
/// Measured under a loaded `cargo test --workspace`: 5.15 MiB of phantom retention against a 1 MiB
/// tolerance (2.6 B/observation, versus the ~24 B/observation the real regression costs) — a pure
/// measurement artefact of WHICH thread ran the drain, with the fix itself working correctly.
///
/// Holding this guard for the measured window makes that thread the only drainer, which is what the
/// assertion always assumed. RE-ENTRANT, so the holder still drives its own drains through the
/// ordinary `metrics::drain_pending()` entry point. Lock ORDER is always `drain_serial` →
/// `flush_lock` (both acquisitions are at the top of their function), so there is no inversion.
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

    /// Held for as long as this thread needs exclusive drain rights. `None` = a re-entrant
    /// acquisition whose outer guard owns the release.
    pub struct Guard(Option<MutexGuard<'static, ()>>);

    impl Drop for Guard {
        fn drop(&mut self) {
            // Clear the flag BEFORE the inner `MutexGuard` field drops (fields drop after
            // `Drop::drop`), so no other thread can take the lock while this one still claims it.
            if self.0.is_some() {
                HELD.with(|h| h.set(false));
            }
        }
    }

    /// Acquire exclusive drain rights, re-entrantly. `std::sync::ReentrantLock` is still unstable
    /// (rust#121440), so this is the two-line equivalent for the one shape we need.
    pub fn lock() -> Guard {
        if HELD.with(Cell::get) {
            return Guard(None);
        }
        let g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        HELD.with(|h| h.set(true));
        Guard(Some(g))
    }
}

/// THE aggregator: sum every thread's cells per slot and push the delta since the last flush into
/// the process-global Prometheus recorder. Called from `metrics::render()` so every scrape (and
/// every test that reads the exposition) observes up-to-date bank totals. Deltas (not absolutes)
/// so banked series compose additively with anything the macro fallback paths emitted on the same
/// series. No-op until the recorder is installed — a handle minted before install would bind to
/// the no-op recorder forever (same contract as the handle cache in `metrics.rs`).
pub fn flush_to_recorder() {
    #[cfg(any(test, feature = "test-support"))]
    let _serial = drain_serial::lock();
    if !crate::metrics::recorder_installed() {
        return;
    }
    let reg = registry();
    let _guard = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());
    let threads: Vec<Arc<ThreadBank>> = reg
        .threads
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();

    // Counters: sum → delta → increment. A slot whose lifetime total is still zero is SKIPPED
    // (no handle minted), so registering slots does not surface zero-valued series that the macro
    // world would not have shown until first increment — /metrics output stays identical.
    let counter_descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in counter_descs.iter().enumerate() {
        let (chunk_i, off) = (i / COUNTER_CHUNK, i % COUNTER_CHUNK);
        let mut sum: u64 = 0;
        for bank in &threads {
            if let Some(chunk) = bank.counters[chunk_i].get() {
                sum = sum.wrapping_add(chunk[off].load(Ordering::Relaxed));
            }
        }
        let prev = desc.flushed.load(Ordering::Relaxed);
        if sum > prev {
            let handle = desc.handle.get_or_init(|| mint_counter(desc));
            handle.increment(sum - prev);
            desc.flushed.store(sum, Ordering::Relaxed);
        }
    }
    drop(counter_descs);

    // Histograms: drain each thread's sample buffer into the recorder. The recorder's own
    // summary/histogram machinery then renders exactly what per-request `record()` calls would
    // have produced — samples are merely delivered at scrape time instead of request time.
    let hist_descs = reg.hists.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in hist_descs.iter().enumerate() {
        let (chunk_i, off) = (i / HIST_CHUNK, i % HIST_CHUNK);
        for bank in &threads {
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

/// THE BANK'S INTERNALS, revealed to a TEST BUILD ONLY.
///
/// The capacity knobs and the per-thread storage itself are implementation detail — nothing outside
/// this module emits through them. But the batteries that pin the retention contract (that
/// `record_inner(_, false)` never materializes a chunk, and that staying under the overflow-drain
/// backstop retains effectively nothing) have to READ the per-thread chunk state and the exact
/// threshold they stay under, or they would be asserting against numbers copied by hand. This module
/// is gated on the same test/`test-support` axis the rest of the test surface uses, so a shipped
/// build reveals none of it.
#[cfg(any(test, feature = "test-support"))]
pub mod bank_internals {
    pub use super::HIST_DRAIN_THRESHOLD;

    /// Has THIS thread materialized the per-thread sample-buffer chunk `slot` lands in?
    ///
    /// The retention contract's sharpest edge: `record_inner(_, false)` must never allocate a chunk
    /// nothing will ever drain. Reading that takes the slot's index and the thread's own chunk
    /// vector, both of which stay private — this is the one question a battery gets to ask.
    pub fn hist_chunk_materialized(slot: super::HistogramSlot) -> bool {
        let idx = slot.0 as usize;
        super::BANK.with(|bank| bank.hists[idx / super::HIST_CHUNK].get().is_some())
    }
}
