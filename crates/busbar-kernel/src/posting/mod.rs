// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POSTER: a unit's counts reach the store ONCE, at its close, as one contribution
//! (MONEY-DESIGN §3c, "Write-before-ack", "The poster: two halves").
//!
//! - A unit's ADMISSION appends a local [`Mark`]: its charge, under its own two op ids. No store
//!   call and no wait: it rides the next round.
//! - A unit's CLOSE hands its [`Contrib`] (its final 1.5.5 bill as RAM `cur` applied it) onto an
//!   UNBOUNDED FIFO under the shard lock that produced it. The queue is bounded by the units in
//!   flight, and a `Drop` cannot wait.
//! - THE SPOOL WRITER drains the queue in ROUNDS: one write and one `fsync` per round
//!   ([`spool::Spool`]), then releases that round's waiters. A round also carries the `sent` record
//!   of the batch it forms from the round's contributions, so the `sent` record is synced before
//!   the first send.
//! - THE STORE SENDER posts each batch as `add_usage_batch` plus `add_metering_batch` under two op
//!   ids. Batches are independent (every delta is non-negative, so no order between cells is kept),
//!   so N concurrent settlements cost one round, one `fsync` and one batch, and nothing holds a
//!   lock across I/O.
//!
//! What an answer proves (rule S5): READY applied; REFUSED nothing applied (split per contribution
//! under new op ids, dead-lettered when still refused alone); Overloaded not applied; Conflict on a
//! spooled op id applied; anything else applied-unknown, replayed with the identical body under the
//! same op id; near retention, dead-lettered `landed-unknown`.
//!
//! Without a data directory the spool is a RAM queue and a waiter is released at READY.
//!
//! THE GATE ([`Gate`]) is read by the admission path itself, from shared stamps: the age of the
//! oldest contribution not yet READY and the age of the store's last round trip (a 1 s probe runs
//! when idle). Over 2 s, admissions answer 503 `DurabilityUnavailable`.

pub mod frame;
pub mod record;
pub mod spool;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
use busbar_contract::records::{MeteringDelta, RecordStore, UsageDelta, UsageLedger};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use serde::{Deserialize, Serialize};

pub use record::{
    usage_body, metering_body, sibling_bucket, CellCount, Contrib, DeadState, Kind, Mark,
    MeterCount, Op, Ops, Rec, Seg, UnitId,
};

/// Admissions are refused while either age is over this (MONEY-DESIGN §3c, "The gate").
pub const GATE_AGE_MS: u64 = 2_000;

/// The idle probe's cadence.
pub const PROBE_EVERY: Duration = Duration::from_secs(1);

/// Every END wait is bounded by this (owner item 15).
pub const END_WAIT: Duration = Duration::from_secs(10);

/// How many batches may be in flight at once.
const MAX_INFLIGHT: usize = 8;

/// An op still applied-unknown this close to the stores' op-id retention can no longer be
/// replayed safely: it is dead-lettered `landed-unknown`.
pub const RETENTION_MARGIN_MS: u64 = (OP_ID_RETENTION_SECS - 3_600) * 1_000;

/// Spool size past which the writer compacts.
const COMPACT_BYTES: u64 = 8 * 1024 * 1024;

fn now_ms() -> u64 {
    crate::store::now_ms()
}

// ── the store seam ───────────────────────────────────────────────────────────────────────────────

/// What the poster and the read-through need of the configured store.
pub trait PostStore: Send + Sync {
    /// `add_usage_batch` under `op`.
    fn add_usage_batch<'a>(
        &'a self,
        op: Op,
        cells: &'a [(String, u64, UsageDelta)],
    ) -> StoreCall<'a, ()>;
    /// `add_metering_batch` under `op`.
    fn add_metering_batch<'a>(&'a self, op: Op, rows: &'a [MeteringDelta]) -> StoreCall<'a, ()>;
    /// A cheap read proving the store answers (`record_get`).
    fn probe(&self) -> StoreCall<'_, ()>;
    /// `get_usage` of one row.
    fn get_usage<'a>(&'a self, bucket: &'a str, window: u64) -> StoreCall<'a, UsageLedger>;
}

/// The configured store's v3 slots, with its 1.5.5 op set for the reads the slots do not carry.
pub struct SlotStore {
    calls: Arc<dyn StoreCalls>,
    records: Arc<dyn RecordStore>,
}

impl SlotStore {
    /// Over `calls`, reading rows through `records`.
    #[must_use]
    pub fn new(calls: Arc<dyn StoreCalls>, records: Arc<dyn RecordStore>) -> Self {
        SlotStore { calls, records }
    }
}

/// The schema the idle probe reads a key of (any answer, present or absent, is a round trip).
pub const PROBE_SCHEMA: &str = "busbar.card.v1";

fn blocking_usage(
    records: Arc<dyn RecordStore>,
    bucket: String,
    window: u64,
) -> StoreCall<'static, UsageLedger> {
    Box::pin(async move {
        let join = tokio::task::spawn_blocking(move || records.get_usage(&bucket, window));
        match join.await {
            Ok(Ok(row)) => Ok(row),
            Ok(Err(e)) => Err(StoreFailure::Failed(e.to_string())),
            Err(e) => Err(StoreFailure::Fault(e.to_string())),
        }
    })
}

impl PostStore for SlotStore {
    fn add_usage_batch<'a>(
        &'a self,
        op: Op,
        cells: &'a [(String, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        Box::pin(async move {
            let borrowed: Vec<(&str, u64, UsageDelta)> = cells
                .iter()
                .map(|(b, w, d)| (b.as_str(), *w, d.clone()))
                .collect();
            self.calls.add_usage_batch(op.0, &borrowed).await
        })
    }

    fn add_metering_batch<'a>(&'a self, op: Op, rows: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        self.calls.add_metering_batch(op.0, rows)
    }

    fn probe(&self) -> StoreCall<'_, ()> {
        Box::pin(async move {
            self.calls
                .record_get(PROBE_SCHEMA, b"\x00probe")
                .await
                .map(|_| ())
        })
    }

    fn get_usage<'a>(&'a self, bucket: &'a str, window: u64) -> StoreCall<'a, UsageLedger> {
        blocking_usage(Arc::clone(&self.records), bucket.to_string(), window)
    }
}

/// A store reached by no door (a test's in-memory store): its 1.5.5 additive ops, which dedupe
/// nothing. Production always opens the store through its door ([`SlotStore`]).
pub struct RecordsOnly(pub Arc<dyn RecordStore>);

impl PostStore for RecordsOnly {
    fn add_usage_batch<'a>(
        &'a self,
        _op: Op,
        cells: &'a [(String, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        let records = Arc::clone(&self.0);
        let cells = cells.to_vec();
        Box::pin(async move {
            let r = tokio::task::spawn_blocking(move || {
                for (b, w, d) in &cells {
                    records.add_usage(b, *w, d)?;
                }
                Ok::<(), busbar_contract::records::RecordStoreError>(())
            })
            .await;
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(StoreFailure::Failed(e.to_string())),
                Err(e) => Err(StoreFailure::Fault(e.to_string())),
            }
        })
    }

    fn add_metering_batch<'a>(&'a self, _op: Op, rows: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        let records = Arc::clone(&self.0);
        let rows = rows.to_vec();
        Box::pin(async move {
            let r = tokio::task::spawn_blocking(move || {
                for d in &rows {
                    records.add_metering(d)?;
                }
                Ok::<(), busbar_contract::records::RecordStoreError>(())
            })
            .await;
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(StoreFailure::Failed(e.to_string())),
                Err(e) => Err(StoreFailure::Fault(e.to_string())),
            }
        })
    }

    fn probe(&self) -> StoreCall<'_, ()> {
        let records = Arc::clone(&self.0);
        Box::pin(async move {
            blocking_usage(records, "e:probe".to_string(), 0)
                .await
                .map(|_| ())
        })
    }

    fn get_usage<'a>(&'a self, bucket: &'a str, window: u64) -> StoreCall<'a, UsageLedger> {
        blocking_usage(Arc::clone(&self.0), bucket.to_string(), window)
    }
}

// ── the gate ─────────────────────────────────────────────────────────────────────────────────────

/// Why the gate is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// A contribution has waited for READY too long.
    Undelivered,
    /// The store has not answered a round trip recently.
    StoreSilent,
    /// The spool's `fsync` failed and no reopen has succeeded.
    SpoolFailed,
    /// Boot has not yet delivered the spool.
    Booting,
}

/// THE GATE'S SHARED STAMPS: written by the hand-off, the sender and the probe; read by the
/// admission path without asking the poster, so a dead poster cannot leave the gate open.
#[derive(Debug, Default)]
pub struct Gate {
    outstanding: Mutex<BTreeSet<(u64, UnitId)>>,
    last_trip_ms: AtomicU64,
    spool_failed: AtomicBool,
    booting: AtomicBool,
    dead_buckets: RwLock<HashMap<String, usize>>,
}

impl Gate {
    fn handed(&self, at_ms: u64, unit: UnitId) {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((at_ms, unit));
    }

    fn delivered(&self, at_ms: u64, unit: UnitId) {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(at_ms, unit));
    }

    /// Stamp a store round trip at `at_ms`.
    pub fn tripped(&self, at_ms: u64) {
        self.last_trip_ms.fetch_max(at_ms, Ordering::Relaxed);
    }

    /// The oldest contribution not yet READY, wall-clock ms.
    #[must_use]
    pub fn oldest_undelivered(&self) -> Option<u64> {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first()
            .map(|(ms, _)| *ms)
    }

    /// How many contributions are not yet READY.
    #[must_use]
    pub fn undelivered(&self) -> usize {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether admissions may pass at `now_ms`.
    ///
    /// # Errors
    ///
    /// Why they may not.
    pub fn check(&self, now_ms: u64) -> Result<(), Closed> {
        if self.booting.load(Ordering::Acquire) {
            return Err(Closed::Booting);
        }
        if self.spool_failed.load(Ordering::Acquire) {
            return Err(Closed::SpoolFailed);
        }
        if self
            .oldest_undelivered()
            .is_some_and(|at| now_ms.saturating_sub(at) > GATE_AGE_MS)
        {
            return Err(Closed::Undelivered);
        }
        let trip = self.last_trip_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(trip) > GATE_AGE_MS {
            return Err(Closed::StoreSilent);
        }
        Ok(())
    }

    /// Whether `bucket` holds a `refused` dead letter (its own admissions are refused until an
    /// operator clears it).
    #[must_use]
    pub fn dead(&self, bucket: &str) -> bool {
        self.dead_buckets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(bucket)
            .is_some_and(|n| *n > 0)
    }

    fn dead_add(&self, cells: &[CellCount], up: bool) {
        let mut map = self
            .dead_buckets
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for c in cells {
            let n = map.entry(c.bucket.clone()).or_insert(0);
            *n = if up { *n + 1 } else { n.saturating_sub(1) };
        }
        map.retain(|_, n| *n > 0);
    }
}

// ── the waiter an END waits on ───────────────────────────────────────────────────────────────────

/// Where a contribution stands, as its END sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durable {
    /// Not yet durable.
    Pending,
    /// Durable: the spool round that carries it synced, or (no data directory) its store READY.
    Yes,
}

/// A unit's END waits on this (MONEY-DESIGN §3c, "Hold-back").
#[derive(Debug, Clone)]
pub struct Ticket(tokio::sync::watch::Receiver<Durable>);

/// Why an END wait ended without durability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDurable {
    /// The bound passed (owner item 15): the END ends with an error.
    TimedOut,
}

impl Ticket {
    /// A ticket already durable (a unit that posts nothing).
    #[must_use]
    pub fn durable() -> Self {
        let (_tx, rx) = tokio::sync::watch::channel(Durable::Yes);
        Ticket(rx)
    }

    /// Whether it is durable now.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        *self.0.borrow() == Durable::Yes
    }

    /// Wait for durability, at most `bound`.
    ///
    /// # Errors
    ///
    /// The bound passed first.
    pub async fn wait(mut self, bound: Duration) -> Result<(), NotDurable> {
        let waited = tokio::time::timeout(bound, self.0.wait_for(|d| *d == Durable::Yes)).await;
        match waited {
            Ok(Ok(_)) => Ok(()),
            // The poster dropped the sender without releasing it: never durable.
            Ok(Err(_)) | Err(_) => {
                if self.is_durable() {
                    Ok(())
                } else {
                    Err(NotDurable::TimedOut)
                }
            }
        }
    }
}

// ── the poster ───────────────────────────────────────────────────────────────────────────────────

/// What is handed to the poster.
#[derive(Debug)]
enum Handoff {
    Mark(Mark),
    Contrib(Contrib, tokio::sync::watch::Sender<Durable>),
}

/// A dead letter: a contribution's op that will not be posted by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetter {
    /// The unit.
    pub unit: UnitId,
    /// Which op.
    pub kind: Kind,
    /// `refused` or `landed-unknown`.
    pub state: DeadState,
    /// Why.
    pub reason: String,
    /// Its usage counts (empty for a metering letter).
    #[serde(default)]
    pub cells: Vec<CellCount>,
    /// Its metering rows (empty for a usage letter).
    #[serde(default)]
    pub metering: Vec<MeterCount>,
    /// When, wall-clock ms.
    pub at_ms: u64,
}

/// The dead-letter file's records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
enum DeadRec {
    Letter(DeadLetter),
    /// The operator's verdict: the letter is gone (landed, or re-posted and READY).
    Cleared { unit: UnitId, kind: Kind },
    /// A re-post under `op`, written before it is sent.
    Reposted { unit: UnitId, kind: Kind, op: Op },
}

/// The operator's verdict on a dead letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A `landed-unknown` letter did land: drop it.
    Landed,
    /// Re-post it under a new op id (a `refused` letter, or a `landed-unknown` one that did not
    /// land).
    Repost,
}

/// Where the poster keeps its records.
#[derive(Debug, Clone)]
pub enum Medium {
    /// A data directory: the spool and the dead-letter file live in it.
    Dir(PathBuf),
    /// No data directory: a RAM queue.
    Memory,
}

/// Counters a test reads.
#[derive(Debug, Default)]
pub struct Stats {
    /// Rounds the writer ran that carried hand-offs.
    pub rounds: AtomicU64,
    /// Batches (ops) sent for the first time.
    pub batches: AtomicU64,
    /// Ops replayed.
    pub replays: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cover {
    Unsent,
    Op(Op),
    Done,
}

#[derive(Debug)]
struct UnitState {
    mark: Option<Mark>,
    contrib: Option<Contrib>,
    usage: Cover,
    metering: Cover,
    /// A crash bill (or a mark posted at shutdown): the mark's usage op covers it.
    crash: Cover,
    waiter: Option<tokio::sync::watch::Sender<Durable>>,
    handed_ms: u64,
}

impl UnitState {
    fn new() -> Self {
        UnitState {
            mark: None,
            contrib: None,
            usage: Cover::Unsent,
            metering: Cover::Unsent,
            crash: Cover::Unsent,
            waiter: None,
            handed_ms: 0,
        }
    }

    fn retired(&self) -> bool {
        match &self.contrib {
            Some(_) => self.usage == Cover::Done && self.metering == Cover::Done,
            None => self.crash == Cover::Done,
        }
    }
}

#[derive(Debug, Clone)]
struct OpState {
    kind: Kind,
    units: Vec<UnitId>,
    at_ms: u64,
    /// A crash bill (the units' marks are the body).
    crash: bool,
    in_flight: bool,
}

#[derive(Debug)]
enum Outcome {
    Applied,
    Conflict,
    Refused(String),
    NotApplied,
    Unknown(String),
}

#[derive(Debug)]
struct Answer {
    op: Op,
    outcome: Outcome,
}

/// The writer-owned state.
struct State {
    units: HashMap<UnitId, UnitState>,
    ops: HashMap<Op, OpState>,
    /// Records that need no `fsync` of their own (READY), riding the next write.
    lazy: Vec<Rec>,
    spool: Option<spool::Spool>,
    dead_file: Option<spool::Ledgerette>,
    dead: Vec<DeadLetter>,
}

struct Inner {
    queue: Mutex<VecDeque<Handoff>>,
    wake: tokio::sync::Notify,
    gate: Arc<Gate>,
    store: Arc<dyn PostStore>,
    memory: bool,
    state: tokio::sync::Mutex<State>,
    answers_tx: tokio::sync::mpsc::UnboundedSender<Answer>,
    answers_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Answer>>,
    stats: Stats,
    fsyncs: Arc<AtomicU64>,
    stopped: AtomicBool,
    /// Units recovered at boot that are not yet delivered: admissions stay refused until 0.
    recovering: AtomicU64,
}

/// THE POSTER: hand-offs in, rounds and batches out.
#[derive(Clone)]
pub struct Poster {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Poster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poster")
            .field("memory", &self.inner.memory)
            .finish_non_exhaustive()
    }
}

/// What boot recovered from the spool and the dead-letter file.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Dead letters standing at boot: a `refused` one goes into RAM `cur` and `posted_hi`, a
    /// `landed-unknown` one into `posted_hi` only.
    pub dead: Vec<DeadLetter>,
    /// Units whose spooled records are being delivered.
    pub units: usize,
}

impl Poster {
    /// A poster over `store`, keeping its records on `medium`. With a data directory the spool is
    /// read back: every unretired mark is posted as its crash bill under its own ops, every
    /// unretired `sent` is replayed under its own op, every contribution never sent is sent, and a
    /// record past retention is dead-lettered `landed-unknown`; admissions stay refused until all of
    /// it is delivered. An `ephemeral` store discards the spool and the dead letters.
    ///
    /// # Errors
    ///
    /// The spool directory could not be read or written.
    pub fn open(
        store: Arc<dyn PostStore>,
        medium: Medium,
        ephemeral: bool,
        syncer: Arc<dyn spool::Syncer>,
    ) -> std::io::Result<(Poster, Recovered)> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(Gate::default());
        gate.tripped(now_ms());
        let mut state = State {
            units: HashMap::new(),
            ops: HashMap::new(),
            lazy: Vec::new(),
            spool: None,
            dead_file: None,
            dead: Vec::new(),
        };
        let mut fsyncs = Arc::new(AtomicU64::new(0));
        let memory = matches!(medium, Medium::Memory);
        if let Medium::Dir(dir) = &medium {
            let spool_dir = dir.join("money-spool");
            let dead = spool::Ledgerette::at(dir.join("money-spool").join("DEADLETTERS"));
            if ephemeral {
                spool::Spool::discard(&spool_dir)?;
                dead.discard()?;
            }
            let (s, recs) = spool::Spool::open(&spool_dir, syncer)?;
            fsyncs = s.fsyncs();
            state.dead = load_dead(&dead)?;
            fold(&mut state, recs);
            state.spool = Some(s);
            state.dead_file = Some(dead);
        }
        let recovered = Recovered {
            dead: state.dead.clone(),
            units: state.units.len(),
        };
        let inner = Arc::new(Inner {
            queue: Mutex::new(VecDeque::new()),
            wake: tokio::sync::Notify::new(),
            gate,
            store,
            memory,
            state: tokio::sync::Mutex::new(state),
            answers_tx: tx,
            answers_rx: tokio::sync::Mutex::new(rx),
            stats: Stats::default(),
            fsyncs,
            stopped: AtomicBool::new(false),
            recovering: AtomicU64::new(recovered.units as u64),
        });
        for d in &recovered.dead {
            if d.state == DeadState::Refused && d.kind == Kind::Usage {
                inner.gate.dead_add(&d.cells, true);
            }
        }
        if recovered.units > 0 {
            inner.gate.booting.store(true, Ordering::Release);
        }
        Ok((Poster { inner }, recovered))
    }

    /// Start the writer and the idle probe on the current runtime.
    pub fn spawn(&self) {
        let writer = self.clone();
        tokio::spawn(async move { writer.run().await });
        let prober = self.clone();
        tokio::spawn(async move { prober.probe_loop().await });
    }

    /// The gate's shared stamps.
    #[must_use]
    pub fn gate(&self) -> Arc<Gate> {
        Arc::clone(&self.inner.gate)
    }

    /// Whether ENDs wait for store READY (no data directory) rather than a spool `fsync`.
    #[must_use]
    pub fn memory(&self) -> bool {
        self.inner.memory
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }

    /// Spool `fsync`s so far (0 without a data directory).
    #[must_use]
    pub fn fsyncs(&self) -> u64 {
        self.inner.fsyncs.load(Ordering::Relaxed)
    }

    /// The store the poster posts to.
    #[must_use]
    pub fn store(&self) -> Arc<dyn PostStore> {
        Arc::clone(&self.inner.store)
    }

    /// HAND OFF a unit's admission mark. Never blocks and never waits.
    pub fn mark(&self, mark: Mark) {
        self.push(Handoff::Mark(mark));
    }

    /// HAND OFF a unit's contribution. Never blocks and never waits; the returned ticket is what
    /// its END waits on.
    #[must_use]
    pub fn contribute(&self, contrib: Contrib) -> Ticket {
        let (tx, rx) = tokio::sync::watch::channel(Durable::Pending);
        self.inner.gate.handed(contrib.at_ms, contrib.unit);
        self.push(Handoff::Contrib(contrib, tx));
        Ticket(rx)
    }

    fn push(&self, h: Handoff) {
        self.inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(h);
        self.inner.wake.notify_one();
    }

    /// The dead letters standing now.
    pub async fn dead_letters(&self) -> Vec<DeadLetter> {
        self.inner.state.lock().await.dead.clone()
    }

    /// THE OPERATOR'S CLEAR of unit `unit`'s `kind` dead letter: `Landed` drops a `landed-unknown`
    /// letter; `Repost` re-posts it under a NEW op id, the `reposted` record synced before the
    /// send, so a crash cannot post it twice. Answers the letter that was cleared.
    ///
    /// # Errors
    ///
    /// No such letter, a `Landed` verdict on a `refused` letter, or the dead-letter file could not
    /// be written.
    pub async fn clear(
        &self,
        unit: UnitId,
        kind: Kind,
        verdict: Verdict,
    ) -> Result<DeadLetter, String> {
        let mut st = self.inner.state.lock().await;
        let at = st
            .dead
            .iter()
            .position(|d| d.unit == unit && d.kind == kind)
            .ok_or_else(|| format!("no dead letter for unit {unit} ({kind:?})"))?;
        let letter = st.dead[at].clone();
        match verdict {
            Verdict::Landed if letter.state == DeadState::Refused => {
                return Err("a refused dead letter never landed: re-post it".to_string())
            }
            Verdict::Landed => {
                dead_append(&st, &DeadRec::Cleared { unit, kind })?;
                st.dead.remove(at);
            }
            Verdict::Repost => {
                let op = Op::mint();
                dead_append(&st, &DeadRec::Reposted { unit, kind, op })?;
                st.dead.remove(at);
                drop(st);
                let poster = self.clone();
                let letter2 = letter.clone();
                tokio::spawn(async move { poster.repost(letter2, op).await });
                if letter.state == DeadState::Refused && kind == Kind::Usage {
                    self.inner.gate.dead_add(&letter.cells, false);
                }
                return Ok(letter);
            }
        }
        if letter.state == DeadState::Refused && kind == Kind::Usage {
            self.inner.gate.dead_add(&letter.cells, false);
        }
        Ok(letter)
    }

    async fn repost(&self, letter: DeadLetter, op: Op) {
        loop {
            let res = match letter.kind {
                Kind::Usage => {
                    let body = usage_body(&letter.cells);
                    self.inner.store.add_usage_batch(op, &body).await
                }
                Kind::Metering => {
                    let body = metering_body(&letter.metering);
                    self.inner.store.add_metering_batch(op, &body).await
                }
            };
            match res {
                Ok(()) | Err(StoreFailure::Conflict) => {
                    self.inner.gate.tripped(now_ms());
                    let st = self.inner.state.lock().await;
                    let _ = dead_append(
                        &st,
                        &DeadRec::Cleared {
                            unit: letter.unit,
                            kind: letter.kind,
                        },
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(unit = %letter.unit, error = %e, "money: a cleared dead letter's re-post did not land; retrying under the same op id");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// THE SHUTDOWN DRAIN: deliver what is queued, at most `grace`; without a data directory, post
    /// every unretired admission mark under its unit's own op ids first (1.5.5's shutdown flush
    /// counted in-flight units `requests +1, billable +1`). Logs what is left undelivered.
    pub async fn drain(&self, grace: Duration) {
        self.inner.wake.notify_one();
        if self.inner.memory {
            let mut st = self.inner.state.lock().await;
            let crash: Vec<UnitId> = st
                .units
                .iter()
                .filter(|(_, u)| u.contrib.is_none() && u.mark.is_some() && u.crash == Cover::Unsent)
                .map(|(id, _)| *id)
                .collect();
            for unit in crash {
                self.crash_bill(&mut st, unit);
            }
            drop(st);
        }
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            self.inner.wake.notify_one();
            let left = {
                let st = self.inner.state.lock().await;
                let queued = self
                    .inner
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len();
                st.units
                    .values()
                    .filter(|u| !(u.contrib.is_none() && u.crash == Cover::Unsent))
                    .count()
                    + queued
            };
            if left == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::error!(
                    undelivered = left,
                    "money: shutdown drain ended with contributions undelivered to the store"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Stop the writer and the probe (a test's restart).
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner.wake.notify_one();
    }

    async fn probe_loop(&self) {
        let mut tick = tokio::time::interval(PROBE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if self.inner.stopped.load(Ordering::Acquire) {
                return;
            }
            let last = self.inner.gate.last_trip_ms.load(Ordering::Relaxed);
            if now_ms().saturating_sub(last) < PROBE_EVERY.as_millis() as u64 {
                continue;
            }
            let probed = self.inner.store.probe().await;
            if probed.is_ok() {
                self.inner.gate.tripped(now_ms());
            }
        }
    }

    // ── the writer ─────────────────────────────────────────────────────────────────────────────

    async fn run(&self) {
        let mut rx = self.inner.answers_rx.lock().await;
        // Boot: deliver what the spool recovered.
        {
            let mut st = self.inner.state.lock().await;
            self.recover(&mut st);
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if self.inner.stopped.load(Ordering::Acquire) {
                return;
            }
            tokio::select! {
                () = self.inner.wake.notified() => {
                    let mut st = self.inner.state.lock().await;
                    self.round(&mut st);
                }
                Some(a) = rx.recv() => {
                    let mut st = self.inner.state.lock().await;
                    self.answer(&mut st, a);
                    while let Ok(a) = rx.try_recv() {
                        self.answer(&mut st, a);
                    }
                    self.round(&mut st);
                }
                _ = tick.tick() => {
                    let mut st = self.inner.state.lock().await;
                    self.idle(&mut st);
                }
            }
        }
    }

    /// ONE ROUND: drain the hand-offs, form a batch from the contributions not yet sent, write the
    /// lot (marks, contributions, the batch's `sent` records, pending READYs) in one write and one
    /// `fsync`, release the round's waiters, then send.
    fn round(&self, st: &mut State) {
        let drained: Vec<Handoff> = self
            .inner
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        let mut recs: Vec<Rec> = Vec::new();
        let mut fresh: Vec<UnitId> = Vec::new();
        for h in drained {
            match h {
                Handoff::Mark(m) => {
                    let u = st.units.entry(m.unit).or_insert_with(UnitState::new);
                    if u.contrib.is_none() {
                        recs.push(Rec::Admitted(m.clone()));
                        u.mark = Some(m);
                    }
                }
                Handoff::Contrib(c, tx) => {
                    let u = st.units.entry(c.unit).or_insert_with(UnitState::new);
                    recs.push(Rec::Contrib(c.clone()));
                    u.handed_ms = c.at_ms;
                    if usage_body(&c.cells).is_empty() {
                        u.usage = Cover::Done;
                    }
                    if c.metering.is_empty() {
                        u.metering = Cover::Done;
                    }
                    u.contrib = Some(c);
                    u.waiter = Some(tx);
                    fresh.push(*u.contrib.as_ref().map(|c| &c.unit).expect("set"));
                }
            }
        }
        if !fresh.is_empty() {
            self.inner.stats.rounds.fetch_add(1, Ordering::Relaxed);
        }
        let failed = st.spool.as_ref().is_some_and(spool::Spool::failed);
        let mut planned: Vec<Op> = Vec::new();
        if !failed {
            planned = self.plan_batches(st, &mut recs);
        }
        if recs.is_empty() {
            self.retire_done(st);
            return;
        }
        let mut lazy = std::mem::take(&mut st.lazy);
        recs.append(&mut lazy);
        let durable = self.write(st, &recs, true);
        if durable {
            // Spool durability releases the round's waiters (data directory).
            if !self.inner.memory {
                for id in &fresh {
                    if let Some(w) = st.units.get_mut(id).and_then(|u| u.waiter.take()) {
                        let _ = w.send(Durable::Yes);
                    }
                }
            }
            for op in planned {
                self.send(st, op);
            }
        } else {
            // The spool failed: its planned batches were never synced, so they are never sent.
            // Every unit not under a synced batch is posted singly from RAM under its own ops.
            for op in planned {
                if let Some(o) = st.ops.remove(&op) {
                    for u in o.units {
                        if let Some(us) = st.units.get_mut(&u) {
                            match o.kind {
                                Kind::Usage => us.usage = Cover::Unsent,
                                Kind::Metering => us.metering = Cover::Unsent,
                            }
                        }
                    }
                }
            }
            self.post_singly(st);
        }
        self.retire_done(st);
    }

    /// Form batches from every contribution with an unsent op kind (unless too many batches are in
    /// flight), pushing their `sent` records. Answers the new ops.
    fn plan_batches(&self, st: &mut State, recs: &mut Vec<Rec>) -> Vec<Op> {
        let in_flight = st.ops.values().filter(|o| o.in_flight).count();
        if in_flight >= MAX_INFLIGHT {
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [Kind::Usage, Kind::Metering] {
            let mut units: Vec<UnitId> = st
                .units
                .iter()
                .filter(|(_, u)| u.contrib.is_some() && *u.cover(kind) == Cover::Unsent)
                .map(|(id, _)| *id)
                .collect();
            if units.is_empty() {
                continue;
            }
            units.sort();
            let op = Op::mint();
            let at_ms = now_ms();
            for u in &units {
                if let Some(us) = st.units.get_mut(u) {
                    *us.cover_mut(kind) = Cover::Op(op);
                }
            }
            recs.push(Rec::Sent {
                op,
                kind,
                units: units.clone(),
                at_ms,
            });
            st.ops.insert(
                op,
                OpState {
                    kind,
                    units,
                    at_ms,
                    crash: false,
                    in_flight: false,
                },
            );
            out.push(op);
        }
        out
    }

    /// Write `recs` to the spool (`synced` or riding without an `fsync`). `false` when the spool is
    /// failed and the records are only in RAM.
    fn write(&self, st: &mut State, recs: &[Rec], synced: bool) -> bool {
        let Some(spool) = st.spool.as_mut() else {
            return true; // no data directory: RAM is the medium
        };
        if spool.failed() {
            if spool.reopen().is_err() {
                self.inner.gate.spool_failed.store(true, Ordering::Release);
                return false;
            }
            // Reopened: rewrite the live state before anything else.
            let live = live_records(st);
            let spool = st.spool.as_mut().expect("present");
            if spool.compact(&live).is_err() {
                self.inner.gate.spool_failed.store(true, Ordering::Release);
                return false;
            }
        }
        let spool = st.spool.as_mut().expect("present");
        let _ = synced; // every write is synced; READYs ride the next round's write
        match spool.append(recs) {
            Ok(()) => {
                self.inner.gate.spool_failed.store(false, Ordering::Release);
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "money spool: a round could not be made durable; admissions are refused and the round is posted from RAM");
                self.inner.gate.spool_failed.store(true, Ordering::Release);
                false
            }
        }
    }

    /// While the spool is failed: every contribution not under a synced batch posts singly under
    /// its unit's own op ids; store READY is its durability.
    fn post_singly(&self, st: &mut State) {
        let singles: Vec<UnitId> = st
            .units
            .iter()
            .filter(|(_, u)| {
                u.contrib.is_some()
                    && (u.usage == Cover::Unsent || u.metering == Cover::Unsent)
            })
            .map(|(id, _)| *id)
            .collect();
        for unit in singles {
            let Some(us) = st.units.get_mut(&unit) else {
                continue;
            };
            let ops = us.contrib.as_ref().map(|c| c.ops).expect("contrib");
            let mut send = Vec::new();
            for (kind, op) in [(Kind::Usage, ops.usage), (Kind::Metering, ops.metering)] {
                if *us.cover(kind) == Cover::Unsent {
                    *us.cover_mut(kind) = Cover::Op(op);
                    send.push((kind, op));
                }
            }
            for (kind, op) in send {
                st.ops.insert(
                    op,
                    OpState {
                        kind,
                        units: vec![unit],
                        at_ms: now_ms(),
                        crash: false,
                        in_flight: false,
                    },
                );
                self.send(st, op);
            }
        }
    }

    fn crash_bill(&self, st: &mut State, unit: UnitId) {
        let Some(us) = st.units.get_mut(&unit) else {
            return;
        };
        let Some(mark) = us.mark.clone() else {
            return;
        };
        let op = mark.ops.usage;
        us.crash = Cover::Op(op);
        if !st.ops.contains_key(&op) {
            st.ops.insert(
                op,
                OpState {
                    kind: Kind::Usage,
                    units: vec![unit],
                    at_ms: now_ms(),
                    crash: true,
                    in_flight: false,
                },
            );
            st.lazy.push(Rec::Sent {
                op,
                kind: Kind::Usage,
                units: vec![unit],
                at_ms: now_ms(),
            });
            st.lazy.push(Rec::CrashBill {
                unit,
                at_ms: now_ms(),
            });
        }
        self.send(st, op);
    }

    /// Boot delivery of the folded spool.
    fn recover(&self, st: &mut State) {
        let now = now_ms();
        // Past retention: dead-letter landed-unknown rather than replay.
        let stale: Vec<Op> = st
            .ops
            .iter()
            .filter(|(_, o)| now.saturating_sub(o.at_ms) > RETENTION_MARGIN_MS)
            .map(|(op, _)| *op)
            .collect();
        for op in stale {
            self.dead_letter(st, op, DeadState::LandedUnknown, "applied-unknown past the op-id retention margin".into());
        }
        // Unretired marks with no contribution: their crash bill, under their own ops.
        let crash: Vec<UnitId> = st
            .units
            .iter()
            .filter(|(_, u)| u.contrib.is_none() && u.mark.is_some() && u.crash == Cover::Unsent)
            .map(|(id, _)| *id)
            .collect();
        for unit in crash {
            self.crash_bill(st, unit);
        }
        // Unretired `sent`s: replayed under their own op ids.
        let pending: Vec<Op> = st.ops.keys().copied().collect();
        for op in pending {
            self.send(st, op);
        }
        // Contributions never sent: the next round batches them.
        self.inner.wake.notify_one();
        self.retire_done(st);
        if st.units.is_empty() {
            self.inner.recovering.store(0, Ordering::Release);
            self.inner.gate.booting.store(false, Ordering::Release);
        }
    }

    fn idle(&self, st: &mut State) {
        if !st.lazy.is_empty() {
            let recs = std::mem::take(&mut st.lazy);
            if !self.write(st, &recs, false) {
                st.lazy = recs;
            }
        }
        if st.spool.as_ref().is_some_and(spool::Spool::failed) {
            // Keep trying to reopen; posting from RAM meanwhile.
            let _ = self.write(st, &[], true);
        }
        // Retention for ops still unknown.
        let now = now_ms();
        let stale: Vec<Op> = st
            .ops
            .iter()
            .filter(|(_, o)| now.saturating_sub(o.at_ms) > RETENTION_MARGIN_MS)
            .map(|(op, _)| *op)
            .collect();
        for op in stale {
            self.dead_letter(st, op, DeadState::LandedUnknown, "applied-unknown past the op-id retention margin".into());
        }
        if st.spool.as_ref().is_some_and(|s| s.bytes() > COMPACT_BYTES) {
            let live = live_records(st);
            if let Some(s) = st.spool.as_mut() {
                if let Err(e) = s.compact(&live) {
                    tracing::warn!(error = %e, "money spool: compaction failed; the old generation stands");
                }
            }
        }
        self.round(st);
    }

    // ── the sender ─────────────────────────────────────────────────────────────────────────────

    fn body_usage(st: &State, o: &OpState) -> Vec<(String, u64, UsageDelta)> {
        let cells = o.units.iter().filter_map(|u| st.units.get(u)).flat_map(|u| {
            if o.crash {
                u.mark.as_ref().map(|m| m.cells.as_slice()).unwrap_or_default()
            } else {
                u.contrib.as_ref().map(|c| c.cells.as_slice()).unwrap_or_default()
            }
        });
        usage_body(cells)
    }

    fn body_metering(st: &State, o: &OpState) -> Vec<MeteringDelta> {
        let rows = o
            .units
            .iter()
            .filter_map(|u| st.units.get(u))
            .flat_map(|u| u.contrib.as_ref().map(|c| c.metering.as_slice()).unwrap_or_default());
        metering_body(rows)
    }

    /// Send `op` (at most one in flight per op): its body derived from its units, deterministic.
    fn send(&self, st: &mut State, op: Op) {
        let Some(o) = st.ops.get(&op).cloned() else {
            return;
        };
        if o.in_flight {
            return;
        }
        if let Some(m) = st.ops.get_mut(&op) {
            m.in_flight = true;
        }
        self.inner.stats.batches.fetch_add(1, Ordering::Relaxed);
        let store = Arc::clone(&self.inner.store);
        let tx = self.inner.answers_tx.clone();
        let gate = Arc::clone(&self.inner.gate);
        match o.kind {
            Kind::Usage => {
                let body = Self::body_usage(st, &o);
                tokio::spawn(async move {
                    let res = if body.is_empty() {
                        Ok(())
                    } else {
                        store.add_usage_batch(op, &body).await
                    };
                    let _ = tx.send(Answer {
                        op,
                        outcome: classify(res, &gate),
                    });
                });
            }
            Kind::Metering => {
                let body = Self::body_metering(st, &o);
                tokio::spawn(async move {
                    let res = if body.is_empty() {
                        Ok(())
                    } else {
                        store.add_metering_batch(op, &body).await
                    };
                    let _ = tx.send(Answer {
                        op,
                        outcome: classify(res, &gate),
                    });
                });
            }
        }
    }

    fn answer(&self, st: &mut State, a: Answer) {
        let Some(o) = st.ops.get_mut(&a.op) else {
            return;
        };
        o.in_flight = false;
        match a.outcome {
            Outcome::Applied => self.applied(st, a.op),
            Outcome::Conflict => {
                tracing::warn!(op = ?a.op, "money: the store already recorded this op id with a body it renders differently; counted as applied");
                self.applied(st, a.op);
            }
            Outcome::NotApplied | Outcome::Unknown(_) => {
                self.inner.stats.replays.fetch_add(1, Ordering::Relaxed);
                let poster = self.clone();
                let op = a.op;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let mut st = poster.inner.state.lock().await;
                    poster.send(&mut st, op);
                });
            }
            Outcome::Refused(why) => self.refused(st, a.op, why),
        }
    }

    fn applied(&self, st: &mut State, op: Op) {
        let Some(o) = st.ops.remove(&op) else {
            return;
        };
        st.lazy.push(Rec::Ready { op });
        for u in &o.units {
            if let Some(us) = st.units.get_mut(u) {
                if o.crash {
                    us.crash = Cover::Done;
                } else {
                    *us.cover_mut(o.kind) = Cover::Done;
                }
            }
        }
        self.retire_done(st);
    }

    /// REFUSED: nothing applied. A batch splits per contribution, each piece under a NEW op id,
    /// the pieces recorded `superseded` in ONE synced append before any is sent. A piece still
    /// refused alone is dead-lettered.
    fn refused(&self, st: &mut State, op: Op, why: String) {
        let Some(o) = st.ops.get(&op).cloned() else {
            return;
        };
        if o.units.len() <= 1 || o.crash {
            self.dead_letter(st, op, DeadState::Refused, why);
            return;
        }
        let pieces: Vec<(UnitId, Op)> = o.units.iter().map(|u| (*u, Op::mint())).collect();
        let rec = Rec::Superseded {
            op,
            kind: o.kind,
            pieces: pieces.clone(),
            at_ms: now_ms(),
        };
        let mut recs = std::mem::take(&mut st.lazy);
        recs.push(rec);
        if !self.write(st, &recs, true) {
            // Not durable: replay later rather than send pieces no record vouches for.
            let poster = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let mut st = poster.inner.state.lock().await;
                poster.send(&mut st, op);
            });
            return;
        }
        st.ops.remove(&op);
        for (unit, piece) in pieces {
            if let Some(us) = st.units.get_mut(&unit) {
                *us.cover_mut(o.kind) = Cover::Op(piece);
            }
            st.ops.insert(
                piece,
                OpState {
                    kind: o.kind,
                    units: vec![unit],
                    at_ms: now_ms(),
                    crash: false,
                    in_flight: false,
                },
            );
            self.send(st, piece);
        }
    }

    fn dead_letter(&self, st: &mut State, op: Op, state: DeadState, reason: String) {
        let Some(o) = st.ops.remove(&op) else {
            return;
        };
        for unit in &o.units {
            let Some(us) = st.units.get(unit) else {
                continue;
            };
            let (cells, metering) = match (o.kind, o.crash) {
                (Kind::Usage, true) => (us.mark.as_ref().map(|m| m.cells.clone()).unwrap_or_default(), Vec::new()),
                (Kind::Usage, false) => (us.contrib.as_ref().map(|c| c.cells.clone()).unwrap_or_default(), Vec::new()),
                (Kind::Metering, _) => (Vec::new(), us.contrib.as_ref().map(|c| c.metering.clone()).unwrap_or_default()),
            };
            let letter = DeadLetter {
                unit: *unit,
                kind: o.kind,
                state,
                reason: reason.clone(),
                cells,
                metering,
                at_ms: now_ms(),
            };
            tracing::error!(unit = %unit, kind = ?o.kind, state = ?state, reason = %reason,
                "money: a contribution was dead-lettered; its buckets refuse admissions until an operator clears it");
            if let Err(e) = dead_append(st, &DeadRec::Letter(letter.clone())) {
                tracing::error!(error = %e, "money: the dead-letter file could not be written");
            }
            if state == DeadState::Refused && o.kind == Kind::Usage {
                self.inner.gate.dead_add(&letter.cells, true);
            }
            st.dead.push(letter);
        }
        let mut recs = Vec::new();
        for unit in &o.units {
            if let Some(us) = st.units.get_mut(unit) {
                if o.crash {
                    us.crash = Cover::Done;
                } else {
                    *us.cover_mut(o.kind) = Cover::Done;
                }
            }
            recs.push(Rec::Dead {
                unit: *unit,
                kind: o.kind,
            });
        }
        let mut all = std::mem::take(&mut st.lazy);
        all.extend(recs);
        if !self.write(st, &all, true) {
            st.lazy = all;
        }
        self.retire_done(st);
    }

    fn retire_done(&self, st: &mut State) {
        let done: Vec<UnitId> = st
            .units
            .iter()
            .filter(|(_, u)| u.retired())
            .map(|(id, _)| *id)
            .collect();
        for id in done {
            if let Some(mut u) = st.units.remove(&id) {
                if let Some(c) = &u.contrib {
                    self.inner.gate.delivered(u.handed_ms.max(c.at_ms), id);
                    self.inner.gate.delivered(c.at_ms, id);
                }
                if let Some(w) = u.waiter.take() {
                    let _ = w.send(Durable::Yes);
                }
            }
        }
        if self.inner.gate.booting.load(Ordering::Acquire) {
            let left = st
                .units
                .values()
                .filter(|u| !(u.contrib.is_none() && u.crash == Cover::Unsent && u.mark.is_some()))
                .count();
            // Recovered units still undelivered keep the gate closed.
            if left == 0 || st.units.values().all(|u| u.waiter.is_some()) {
                self.inner.recovering.store(0, Ordering::Release);
                self.inner.gate.booting.store(false, Ordering::Release);
            }
        }
    }
}

impl UnitState {
    fn cover(&self, kind: Kind) -> &Cover {
        match kind {
            Kind::Usage => &self.usage,
            Kind::Metering => &self.metering,
        }
    }

    fn cover_mut(&mut self, kind: Kind) -> &mut Cover {
        match kind {
            Kind::Usage => &mut self.usage,
            Kind::Metering => &mut self.metering,
        }
    }
}

fn classify(res: Result<(), StoreFailure>, gate: &Gate) -> Outcome {
    let out = match res {
        Ok(()) => Outcome::Applied,
        Err(StoreFailure::Conflict) => Outcome::Conflict,
        Err(StoreFailure::Refused(t)) => Outcome::Refused(t),
        Err(StoreFailure::Overloaded) => Outcome::NotApplied,
        Err(StoreFailure::Failed(t) | StoreFailure::Fault(t)) => Outcome::Unknown(t),
    };
    if matches!(out, Outcome::Applied | Outcome::Conflict | Outcome::Refused(_)) {
        gate.tripped(now_ms());
    }
    out
}

fn dead_append(st: &State, rec: &DeadRec) -> Result<(), String> {
    match &st.dead_file {
        Some(f) => f
            .append(&[serde_json::to_vec(rec).unwrap_or_default()])
            .map_err(|e| e.to_string()),
        None => Ok(()),
    }
}

fn load_dead(f: &spool::Ledgerette) -> std::io::Result<Vec<DeadLetter>> {
    let mut out: Vec<DeadLetter> = Vec::new();
    for body in f.read()? {
        match serde_json::from_slice::<DeadRec>(&body) {
            Ok(DeadRec::Letter(l)) => out.push(l),
            Ok(DeadRec::Cleared { unit, kind } | DeadRec::Reposted { unit, kind, .. }) => {
                out.retain(|l| !(l.unit == unit && l.kind == kind));
            }
            Err(_) => {}
        }
    }
    Ok(out)
}

/// Fold the spool's records into writer state.
fn fold(st: &mut State, recs: Vec<Rec>) {
    let mut ready: HashSet<Op> = HashSet::new();
    let mut sent: Vec<(Op, Kind, Vec<UnitId>, u64, bool)> = Vec::new();
    let mut superseded: HashMap<Op, Vec<(UnitId, Op)>> = HashMap::new();
    let mut superseded_at: HashMap<Op, u64> = HashMap::new();
    let mut crash_units: HashSet<UnitId> = HashSet::new();
    let mut dead: Vec<(UnitId, Kind)> = Vec::new();
    for r in recs {
        match r {
            Rec::Admitted(m) => {
                let u = st.units.entry(m.unit).or_insert_with(UnitState::new);
                u.mark = Some(m);
            }
            Rec::Contrib(c) => {
                let u = st.units.entry(c.unit).or_insert_with(UnitState::new);
                if usage_body(&c.cells).is_empty() {
                    u.usage = Cover::Done;
                }
                if c.metering.is_empty() {
                    u.metering = Cover::Done;
                }
                u.handed_ms = c.at_ms;
                u.contrib = Some(c);
            }
            Rec::Sent {
                op,
                kind,
                units,
                at_ms,
            } => sent.push((op, kind, units, at_ms, false)),
            Rec::CrashBill { unit, .. } => {
                crash_units.insert(unit);
            }
            Rec::Ready { op } => {
                ready.insert(op);
            }
            Rec::Superseded {
                op, pieces, at_ms, ..
            } => {
                superseded_at.insert(op, at_ms);
                superseded.insert(op, pieces);
            }
            Rec::Dead { unit, kind } => dead.push((unit, kind)),
        }
    }
    // A crash-bill `sent` is the one whose op is its unit's own mark usage op.
    for s in &mut sent {
        if s.2.len() == 1
            && crash_units.contains(&s.2[0])
            && st
                .units
                .get(&s.2[0])
                .and_then(|u| u.mark.as_ref())
                .is_some_and(|m| m.ops.usage == s.0)
            && st.units.get(&s.2[0]).is_some_and(|u| u.contrib.is_none())
        {
            s.4 = true;
        }
    }
    let mut ops: Vec<(Op, Kind, Vec<UnitId>, u64, bool)> = sent;
    for (op, pieces) in &superseded {
        let kind = ops.iter().find(|s| s.0 == *op).map(|s| s.1);
        let at = superseded_at.get(op).copied().unwrap_or(0);
        if let Some(kind) = kind {
            for (unit, piece) in pieces {
                ops.push((*piece, kind, vec![*unit], at, false));
            }
        }
    }
    for (op, kind, units, at_ms, crash) in ops {
        let done = ready.contains(&op);
        let replaced = superseded.contains_key(&op);
        for u in &units {
            let Some(us) = st.units.get_mut(u) else {
                continue;
            };
            let cover = if crash {
                &mut us.crash
            } else {
                us.cover_mut(kind)
            };
            if *cover == Cover::Done {
                continue;
            }
            *cover = if done {
                Cover::Done
            } else if replaced {
                *cover
            } else {
                Cover::Op(op)
            };
        }
        if !done && !replaced {
            st.ops.insert(
                op,
                OpState {
                    kind,
                    units,
                    at_ms,
                    crash,
                    in_flight: false,
                },
            );
        }
    }
    for (unit, kind) in dead {
        if let Some(us) = st.units.get_mut(&unit) {
            if us.contrib.is_none() {
                us.crash = Cover::Done;
            } else {
                *us.cover_mut(kind) = Cover::Done;
            }
        }
    }
    // A mark retired by its unit's contribution is done; a retired unit leaves.
    st.units.retain(|_, u| !u.retired());
    // Ops whose every unit retired leave too.
    let live: HashSet<UnitId> = st.units.keys().copied().collect();
    st.ops.retain(|_, o| o.units.iter().any(|u| live.contains(u)));
}

/// The live records a compaction (or a reopen after a failed spool) writes: per live unit its
/// mark or contribution and the state of each op kind; per pending op its `sent`.
fn live_records(st: &State) -> Vec<Rec> {
    let mut out = Vec::new();
    let mut ops: BTreeMap<Op, &OpState> = BTreeMap::new();
    let mut ids: Vec<&UnitId> = st.units.keys().collect();
    ids.sort();
    for id in ids {
        let u = &st.units[id];
        if let Some(m) = &u.mark {
            if u.contrib.is_none() {
                out.push(Rec::Admitted(m.clone()));
            }
        }
        if let Some(c) = &u.contrib {
            out.push(Rec::Contrib(c.clone()));
        }
        for kind in [Kind::Usage, Kind::Metering] {
            if u.contrib.is_some() && *u.cover(kind) == Cover::Done {
                out.push(Rec::Dead { unit: *id, kind });
            }
        }
    }
    for (op, o) in &st.ops {
        ops.insert(*op, o);
    }
    for (op, o) in ops {
        out.push(Rec::Sent {
            op,
            kind: o.kind,
            units: o.units.clone(),
            at_ms: o.at_ms,
        });
        if o.crash {
            if let Some(u) = o.units.first() {
                out.push(Rec::CrashBill {
                    unit: *u,
                    at_ms: o.at_ms,
                });
            }
        }
    }
    out
}

/// A temporary directory removed on drop (the spool's own tests and the poster's).
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct TmpDir(PathBuf);

#[cfg(any(test, feature = "test-support"))]
impl TmpDir {
    /// A fresh, empty directory under the system temp dir.
    #[must_use]
    pub fn new() -> Self {
        let mut raw = [0u8; 8];
        let _ = getrandom::fill(&mut raw);
        let p = std::env::temp_dir().join(format!("busbar-money-{}", hex::encode(raw)));
        std::fs::create_dir_all(&p).expect("temp dir");
        TmpDir(p)
    }

    /// Its path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Default for TmpDir {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
#[path = "tests/poster_tests.rs"]
mod tests;
