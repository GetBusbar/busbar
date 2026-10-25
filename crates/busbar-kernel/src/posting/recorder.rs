// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDER: counts reach the store OFF the request path (MONEY-DESIGN §3c, OWNER RULING
//! 2026-10-25: "Stores need to not be in the hot path; latency is crucial").
//!
//! - The request path only emits deltas into its budget shard's pending map ([`Ledger`]).
//! - THE SPOOLER, every flush window, takes the pending maps one shard at a time, builds ONE batch
//!   with a monotonic SEQUENCE and two op ids, and (with a data directory) appends and `fsync`s it.
//! - THE SENDER posts batches in sequence order, exactly ONE in flight, so a refund's `-1` never
//!   lands before the `+1` it cancels. A synced `sent` record precedes a batch's first send; a run
//!   of never-sent batches may be merged under fresh op ids; a sent batch only ever replays.
//!
//! What an answer proves (S5): READY applied; Conflict on a spooled op applied (alarmed); REFUSED
//! nothing applied, so the op splits per cell (or metering row) under new op ids, and a piece still
//! refused alone is dead-lettered; Overloaded not applied, retried; anything else applied-unknown,
//! replayed with the identical body under the same op id; near the op-id retention, dead-lettered
//! `landed-unknown` for an operator's verdict.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
use busbar_contract::records::{MeteringDelta, RecordStore, UsageDelta, UsageLedger};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use serde::{Deserialize, Serialize};

use super::record::{self, Batch, CellCount, DeadState, Kind, Op, Part, Rec};
use super::spool::{self, Ledgerette, Spool};

/// Strict mode refuses when an age passes this.
pub const STRICT_AGE_MS: u64 = 2_000;

/// The idle probe's cadence.
pub const PROBE_EVERY: Duration = Duration::from_secs(1);

/// Boot replay's deadline: past it the boot fails, as hydrate's store error does.
pub const REPLAY_DEADLINE: Duration = Duration::from_secs(120);

/// An op still applied-unknown this close to the stores' op-id retention can no longer be replayed
/// safely: it is dead-lettered `landed-unknown`.
pub const RETENTION_MARGIN_MS: u64 = (OP_ID_RETENTION_SECS - 3_600) * 1_000;

/// The spool is compacted (to nothing) when the queue is empty and it is past this size.
const COMPACT_BYTES: u64 = 4 * 1024 * 1024;

/// The pause before an unresolved op is replayed.
const REPLAY_PAUSE: Duration = Duration::from_millis(200);

/// An op applied-unknown for this long WHILE THE STORE'S PROBES SUCCEED is dead-lettered
/// `landed-unknown`. While probes fail it is retried with backoff without limit and never
/// dead-lettered (MONEY-DESIGN §3c).
pub const MAX_UNKNOWN: Duration = Duration::from_secs(10 * 60);

/// Each refusal met during boot replay extends its deadline by this.
pub const REPLAY_PER_REFUSAL: Duration = Duration::from_secs(30);

/// A merged batch carries at most this many cells ...
pub const MERGE_MAX_CELLS: usize = 4_096;

/// ... and at most this many encoded bytes.
pub const MERGE_MAX_BYTES: usize = 256 * 1024;

fn now_ms() -> u64 {
    crate::store::now_ms()
}

// ── the seams ────────────────────────────────────────────────────────────────────────────────────

/// What the recorder takes from and reports to: the governance book's pending deltas.
pub trait Ledger: Send + Sync {
    /// Every shard's pending deltas, taken one shard at a time (their positive parts join
    /// `posted_hi` as they are taken).
    fn take_pending(&self) -> Vec<CellCount>;
    /// `cells` ride batch `seq`: their RAM cells stay resident until a batch at or above `seq` is
    /// READY.
    fn carried(&self, cells: &[CellCount], seq: u64);
    /// The pending metering rows.
    fn take_metering(&self) -> Vec<MeteringDelta>;
    /// `cells` of batch `seq` answered READY (or were dead-lettered): their negative parts join
    /// `posted_hi`, and a cell no later batch carries may leave RAM again.
    fn landed(&self, cells: &[CellCount], seq: u64);
    /// `cells` were dead-lettered `refused`: they will never be in the store, so their positive
    /// parts leave `posted_hi`.
    fn unposted(&self, cells: &[CellCount]);
    /// A cleared `refused` letter's `cells` were re-posted and answered READY: they are in the
    /// store now.
    fn reposted(&self, cells: &[CellCount]);
}

/// What the recorder and the fleet snapshot need of the configured store.
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

/// The schema the idle probe reads a key of (any answer, present or absent, is a round trip).
pub const PROBE_SCHEMA: &str = "busbar.card.v1";

/// The configured store's v3 slots.
pub struct SlotStore {
    calls: Arc<dyn StoreCalls>,
}

impl SlotStore {
    /// Over `calls`.
    #[must_use]
    pub fn new(calls: Arc<dyn StoreCalls>) -> Self {
        SlotStore { calls }
    }
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
        self.calls.get_usage(bucket, window)
    }
}

/// A store reached by no door (a test's in-memory store): its 1.5.5 additive ops, which dedupe
/// nothing. Production always opens the store through its door ([`SlotStore`]).
pub struct RecordsOnly(pub Arc<dyn RecordStore>);

fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, busbar_contract::records::RecordStoreError> + Send + 'static,
) -> StoreCall<'static, T> {
    Box::pin(async move {
        match tokio::task::spawn_blocking(f).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(StoreFailure::Failed(e.to_string())),
            Err(e) => Err(StoreFailure::Fault(e.to_string())),
        }
    })
}

impl PostStore for RecordsOnly {
    fn add_usage_batch<'a>(
        &'a self,
        _op: Op,
        cells: &'a [(String, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        let records = Arc::clone(&self.0);
        let cells = cells.to_vec();
        blocking(move || {
            for (b, w, d) in &cells {
                records.add_usage(b, *w, d)?;
            }
            Ok(())
        })
    }

    fn add_metering_batch<'a>(&'a self, _op: Op, rows: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        let records = Arc::clone(&self.0);
        let rows = rows.to_vec();
        blocking(move || {
            for d in &rows {
                records.add_metering(d)?;
            }
            Ok(())
        })
    }

    fn probe(&self) -> StoreCall<'_, ()> {
        let records = Arc::clone(&self.0);
        blocking(move || records.get_usage("e:probe", 0).map(|_| ()))
    }

    fn get_usage<'a>(&'a self, bucket: &'a str, window: u64) -> StoreCall<'a, UsageLedger> {
        let records = Arc::clone(&self.0);
        let bucket = bucket.to_string();
        blocking(move || records.get_usage(&bucket, window))
    }
}

// ── the stamps strict mode reads ─────────────────────────────────────────────────────────────────

/// Why spend cannot be recorded (strict mode's 503 reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// A delta has waited for READY too long (or the spooler stopped taking).
    Undelivered,
    /// The store has not answered a round trip recently.
    StoreSilent,
    /// The data directory's spool has not synced recently.
    SpoolStalled,
    /// A capped bucket's fleet snapshot read has failed for too long.
    SnapshotStale,
}

impl Closed {
    /// The explanation the 503 and its audit record carry.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Closed::Undelivered => "spend recorded on this node has not reached the store for over 2 s",
            Closed::StoreSilent => "the store has not answered for over 2 s",
            Closed::SpoolStalled => "the spend spool on the data directory has not synced for over 2 s",
            Closed::SnapshotStale => {
                "the fleet's spend for a capped bucket could not be read for over 5 s"
            }
        }
    }
}

/// SHARED TIMESTAMPS: written by the spooler, the sender and the probe; read by the admission path
/// without asking them, so a dead task cannot leave strict mode open.
#[derive(Debug)]
pub struct Stamps {
    last_trip_ms: AtomicU64,
    last_take_ms: AtomicU64,
    /// The oldest unresolved batch's take, `u64::MAX` for none (dead letters excluded).
    oldest_ms: AtomicU64,
    /// The spool's last successful sync (or idle check); `u64::MAX` without a data directory.
    spool_ok_ms: AtomicU64,
    /// The flush window, ms.
    window_ms: AtomicU64,
}

impl Stamps {
    fn new(window_ms: u64, spooled: bool) -> Self {
        let now = now_ms();
        Stamps {
            last_trip_ms: AtomicU64::new(now),
            last_take_ms: AtomicU64::new(now),
            oldest_ms: AtomicU64::new(u64::MAX),
            spool_ok_ms: AtomicU64::new(if spooled { now } else { u64::MAX }),
            window_ms: AtomicU64::new(window_ms),
        }
    }

    /// Stamp a store round trip at `at_ms`.
    pub fn tripped(&self, at_ms: u64) {
        self.last_trip_ms.fetch_max(at_ms, Ordering::Relaxed);
    }

    /// Whether spend can be recorded at `now_ms`, from the stamps alone.
    ///
    /// # Errors
    ///
    /// Why it cannot.
    pub fn check(&self, now_ms: u64) -> Result<(), Closed> {
        let window = self.window_ms.load(Ordering::Relaxed);
        let age = |at: u64| now_ms.saturating_sub(at);
        if age(self.last_take_ms.load(Ordering::Relaxed)) > STRICT_AGE_MS + window {
            return Err(Closed::Undelivered);
        }
        let oldest = self.oldest_ms.load(Ordering::Relaxed);
        if oldest != u64::MAX && age(oldest) > STRICT_AGE_MS {
            return Err(Closed::Undelivered);
        }
        let spool = self.spool_ok_ms.load(Ordering::Relaxed);
        if spool != u64::MAX && age(spool) > STRICT_AGE_MS + window {
            return Err(Closed::SpoolStalled);
        }
        if age(self.last_trip_ms.load(Ordering::Relaxed)) > STRICT_AGE_MS {
            return Err(Closed::StoreSilent);
        }
        Ok(())
    }
}

// ── dead letters ─────────────────────────────────────────────────────────────────────────────────

/// A dead letter: counts that will not be posted by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetter {
    /// Its id (unique on this node's dead-letter file).
    pub id: u64,
    /// Which op: a usage letter holds cells, a metering letter rows.
    pub kind: Kind,
    /// `refused` or `landed-unknown`.
    pub state: DeadState,
    /// Why.
    pub reason: String,
    /// Its usage cells (later deltas for the same `(bucket, window)` fold in while it stands).
    #[serde(default)]
    pub cells: Vec<CellCount>,
    /// Its metering rows.
    #[serde(default)]
    pub metering: Vec<MeteringDelta>,
    /// When, wall-clock ms.
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
enum DeadRec {
    /// The letter as it now stands (a later record for the same id replaces it).
    Letter(DeadLetter),
    /// Gone: landed, or re-posted and READY.
    Cleared { id: u64 },
    /// A re-post under `op`, written before it is sent.
    Reposted { id: u64, op: Op },
}

/// The operator's verdict on a dead letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A `landed-unknown` letter did land: drop it.
    Landed,
    /// Re-post it under a new op id.
    Repost,
}

// ── the queue ────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum KindState {
    Pending,
    Done,
    /// A refused op, bisected: every part, `(part, done)`, in index order.
    Parts(Vec<(Part, bool)>),
}

#[derive(Debug, Clone)]
struct Entry {
    batch: Batch,
    sent: bool,
    usage: KindState,
    metering: KindState,
    /// How long it has been applied-unknown while the store's probes succeeded, ms (this boot).
    unknown_ms: u64,
    /// The last send's answer time, wall-clock ms.
    last_answer_ms: Option<u64>,
}

impl Entry {
    fn new(batch: Batch) -> Self {
        let usage = if batch.cells.is_empty() {
            KindState::Done
        } else {
            KindState::Pending
        };
        let metering = if batch.metering.is_empty() {
            KindState::Done
        } else {
            KindState::Pending
        };
        Entry {
            batch,
            sent: false,
            usage,
            metering,
            unknown_ms: 0,
            last_answer_ms: None,
        }
    }

    fn done(&self) -> bool {
        self.usage == KindState::Done && self.metering == KindState::Done
    }

    fn kind(&mut self, k: Kind) -> &mut KindState {
        match k {
            Kind::Usage => &mut self.usage,
            Kind::Metering => &mut self.metering,
        }
    }

    fn len(&self, k: Kind) -> usize {
        match k {
            Kind::Usage => self.batch.cells.len(),
            Kind::Metering => self.batch.metering.len(),
        }
    }

    fn op(&self, k: Kind) -> Op {
        match k {
            Kind::Usage => self.batch.usage_op,
            Kind::Metering => self.batch.metering_op,
        }
    }
}

#[derive(Default)]
struct Queue {
    entries: VecDeque<Entry>,
    next_seq: u64,
    /// `(bucket, last sequence filtered)`.
    dropped: Vec<(String, u64)>,
    dead: Vec<DeadLetter>,
    next_dead: u64,
}

impl Queue {
    /// The standing `refused` letter holding `(bucket, window)`: later deltas fold into it.
    fn absorbing(&self, bucket: &str, window: u64) -> Option<usize> {
        self.dead.iter().position(|d| {
            d.state == DeadState::Refused
                && d.cells.iter().any(|c| c.bucket == bucket && c.window == window)
        })
    }

    /// Whether batch `seq` leaves `bucket` out.
    fn drops(&self, bucket: &str, seq: u64) -> bool {
        self.dropped.iter().any(|(b, s)| b == bucket && seq <= *s)
    }
}

/// Where the recorder keeps its records.
#[derive(Debug, Clone)]
pub enum Medium {
    /// A data directory: the spool and the dead-letter file live under it.
    Dir(PathBuf),
    /// No data directory: a RAM queue.
    Memory,
}

/// Counters a test reads.
#[derive(Debug, Default)]
pub struct Stats {
    /// Batches the spooler formed.
    pub batches: AtomicU64,
    /// Store sends (first sends and replays, whole ops and parts).
    pub sends: AtomicU64,
    /// Replays of an unresolved op.
    pub replays: AtomicU64,
    /// Merges of never-sent batches.
    pub merges: AtomicU64,
    /// REFUSED answers met.
    pub refusals: AtomicU64,
}

/// THE RECORDER of one opened store.
pub struct Recorder {
    ledger: Arc<dyn Ledger>,
    store: Arc<dyn PostStore>,
    spool: Option<Mutex<Spool>>,
    dead_file: Option<Ledgerette>,
    queue: Mutex<Queue>,
    stamps: Arc<Stamps>,
    stats: Stats,
    wake_sender: tokio::sync::Notify,
    stopped: AtomicBool,
    window: Duration,
    /// Serializes the sender's work (the task and a boot or shutdown drain never interleave).
    sending: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("spooled", &self.spool.is_some())
            .finish_non_exhaustive()
    }
}

/// What the spool and the dead-letter file held at open.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Unresolved batches to deliver before hydrate.
    pub batches: usize,
    /// Their cells (the replay deadline grows with them).
    pub cells: usize,
    /// The `refused` dead letters' cells: RAM `cur` counts them (not `posted_hi`). A
    /// `landed-unknown` letter is never added to `cur`.
    pub refused_cells: Vec<CellCount>,
}

impl Recovered {
    /// Boot replay's deadline: 120 s, plus 2 s per 4,096 backlog cells.
    #[must_use]
    pub fn deadline(&self) -> Duration {
        let per = u64::try_from(self.cells.div_ceil(MERGE_MAX_CELLS)).unwrap_or(u64::MAX);
        REPLAY_DEADLINE + Duration::from_secs(per.saturating_mul(2))
    }
}

fn io_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl Recorder {
    /// A recorder over `store`, taking from `ledger` every `window`, keeping its records on
    /// `medium`. With a data directory the spool and dead letters are read back (an `ephemeral`
    /// store discards both first).
    ///
    /// # Errors
    ///
    /// The data directory could not be read or written.
    pub fn open(
        ledger: Arc<dyn Ledger>,
        store: Arc<dyn PostStore>,
        medium: &Medium,
        ephemeral: bool,
        window: Duration,
        syncer: Arc<dyn spool::Syncer>,
    ) -> Result<(Arc<Recorder>, Recovered), String> {
        let mut queue = Queue::default();
        let (spool, dead_file) = match medium {
            Medium::Dir(dir) => {
                let spool_dir = dir.join("money-spool");
                let dead = Ledgerette::at(spool_dir.join("DEADLETTERS"));
                if ephemeral {
                    Spool::discard(&spool_dir).map_err(io_err)?;
                    dead.discard().map_err(io_err)?;
                }
                let (s, recs) = Spool::open(&spool_dir, syncer).map_err(io_err)?;
                fold(&mut queue, recs);
                for body in dead.read().map_err(io_err)? {
                    match serde_json::from_slice::<DeadRec>(&body) {
                        Ok(DeadRec::Letter(l)) => {
                            queue.next_dead = queue.next_dead.max(l.id + 1);
                            queue.dead.retain(|d| d.id != l.id);
                            queue.dead.push(l);
                        }
                        Ok(DeadRec::Cleared { id } | DeadRec::Reposted { id, .. }) => {
                            queue.dead.retain(|d| d.id != id);
                        }
                        Err(_) => {}
                    }
                }
                (Some(Mutex::new(s)), Some(dead))
            }
            Medium::Memory => (None, None),
        };
        let recovered = Recovered {
            batches: queue.entries.len(),
            cells: queue.entries.iter().map(|e| e.batch.cells.len()).sum(),
            refused_cells: queue
                .dead
                .iter()
                .filter(|d| d.state == DeadState::Refused)
                .flat_map(|d| d.cells.clone())
                .collect(),
        };
        let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
        let rec = Arc::new(Recorder {
            ledger,
            store,
            stamps: Arc::new(Stamps::new(window_ms, spool.is_some())),
            spool,
            dead_file,
            queue: Mutex::new(queue),
            stats: Stats::default(),
            wake_sender: tokio::sync::Notify::new(),
            stopped: AtomicBool::new(false),
            window,
            sending: tokio::sync::Mutex::new(()),
        });
        rec.restamp();
        Ok((rec, recovered))
    }

    /// The shared stamps strict mode reads.
    #[must_use]
    pub fn stamps(&self) -> Arc<Stamps> {
        Arc::clone(&self.stamps)
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> Arc<dyn PostStore> {
        Arc::clone(&self.store)
    }

    /// Unresolved batches.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.lock().entries.len()
    }

    /// The dead letters standing now.
    #[must_use]
    pub fn dead_letters(&self) -> Vec<DeadLetter> {
        self.lock().dead.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Append `recs` to the spool and sync them (no-op without a data directory).
    fn spool(&self, recs: &[Rec]) -> Result<(), String> {
        let Some(spool) = &self.spool else {
            return Ok(());
        };
        let mut s = spool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.failed() {
            s.reopen().map_err(io_err)?;
        }
        s.append(recs).map_err(io_err)?;
        self.stamps.spool_ok_ms.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    fn dead_append(&self, rec: &DeadRec) {
        if let Some(f) = &self.dead_file {
            if let Err(e) = f.append(&[serde_json::to_vec(rec).unwrap_or_default()]) {
                tracing::error!(error = %e, "money: the dead-letter file could not be written");
            }
        }
    }

    /// Recompute the oldest-unresolved stamp (dead letters are not in the queue, so excluded).
    fn restamp(&self) {
        let oldest = self
            .lock()
            .entries
            .iter()
            .map(|e| e.batch.at_ms)
            .min()
            .unwrap_or(u64::MAX);
        self.stamps.oldest_ms.store(oldest, Ordering::Relaxed);
    }

    /// Start the spooler, the sender and the idle probe on the current runtime.
    pub fn spawn(self: &Arc<Self>) {
        let spooler = Arc::clone(self);
        tokio::spawn(async move { spooler.spool_loop().await });
        let sender = Arc::clone(self);
        tokio::spawn(async move { sender.send_loop().await });
        let prober = Arc::clone(self);
        tokio::spawn(async move { prober.probe_loop().await });
    }

    /// Stop the tasks (a test's restart; a process exit).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake_sender.notify_one();
    }

    // ── the spooler ────────────────────────────────────────────────────────────────────────────

    async fn spool_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.window);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let me = Arc::clone(&self);
            // The take and the `fsync` run on the blocking pool: the spooler never parks a runtime
            // worker on a disk.
            let _ = tokio::task::spawn_blocking(move || me.take_once()).await;
        }
    }

    /// ONE TAKE: the pending maps into one batch with the next SEQUENCE (dead-lettered cells folded
    /// into their letters), spooled and synced, queued for the sender. Answers whether a batch was
    /// formed.
    pub fn take_once(&self) -> bool {
        let taken_at = now_ms();
        let cells = self.ledger.take_pending();
        let metering = self.ledger.take_metering();
        self.stamps.last_take_ms.store(taken_at, Ordering::Relaxed);
        let mut cells = record::merged(&cells);
        // Later deltas of a dead-lettered (bucket, window) fold into its letter, never posted.
        let mut folded: Vec<(DeadLetter, CellCount)> = Vec::new();
        {
            let mut q = self.lock();
            cells.retain(|c| match q.absorbing(&c.bucket, c.window) {
                Some(i) => {
                    let letter = &mut q.dead[i];
                    match letter
                        .cells
                        .iter_mut()
                        .find(|d| d.bucket == c.bucket && d.window == c.window)
                    {
                        Some(d) => d.merge(c),
                        None => letter.cells.push(c.clone()),
                    }
                    folded.push((letter.clone(), c.clone()));
                    false
                }
                None => true,
            });
        }
        for (letter, cell) in folded {
            self.ledger.unposted(std::slice::from_ref(&cell));
            self.dead_append(&DeadRec::Letter(letter));
        }
        if cells.is_empty() && metering.is_empty() {
            if self.spool.is_some() {
                self.stamps.spool_ok_ms.store(taken_at, Ordering::Relaxed);
            }
            self.compact_if_idle();
            return false;
        }
        // Capped like a merge: a window that holds more is several batches, in sequence order.
        let chunks = chunked(cells, metering);
        for (cells, metering) in chunks {
            let batch = {
                let mut q = self.lock();
                let seq = q.next_seq;
                q.next_seq += 1;
                Batch {
                    seq,
                    usage_op: Op::mint(),
                    metering_op: Op::mint(),
                    cells,
                    metering,
                    at_ms: taken_at,
                }
            };
            self.ledger.carried(&batch.cells, batch.seq);
            self.stats.batches.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = self.spool(&[Rec::Batch(batch.clone())]) {
                // The batch stays in RAM; the spool's age feeds strict mode and is alarmed.
                tracing::error!(error = %e, seq = batch.seq,
                    "money spool: a batch could not be made durable on the data directory; it is held in RAM and still sent");
            }
            self.lock().entries.push_back(Entry::new(batch));
        }
        self.restamp();
        self.wake_sender.notify_one();
        true
    }

    fn compact_if_idle(&self) {
        let Some(spool) = &self.spool else {
            return;
        };
        let q = self.lock();
        if !q.entries.is_empty() {
            return;
        }
        let drops: Vec<Rec> = q
            .dropped
            .iter()
            .filter(|(_, s)| *s >= q.next_seq)
            .map(|(b, s)| Rec::Drop {
                bucket: b.clone(),
                seq: *s,
            })
            .collect();
        drop(q);
        let mut s = spool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.bytes() > COMPACT_BYTES {
            // Nothing unresolved: the live generation is only the drops still ahead of the queue.
            if let Err(e) = s.compact(&drops) {
                tracing::warn!(error = %e, "money spool: compaction failed; the old generation stands");
            }
        }
    }

    // ── the sender ─────────────────────────────────────────────────────────────────────────────

    async fn send_loop(self: Arc<Self>) {
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let progressed = self.send_front().await;
            if !progressed {
                tokio::select! {
                    () = self.wake_sender.notified() => {}
                    () = tokio::time::sleep(REPLAY_PAUSE) => {}
                }
            }
        }
    }

    /// Work the LOWEST unresolved sequence once: merge a never-sent run, record `sent`, then send
    /// or replay its two ops (and their parts, one at a time). Answers whether it resolved a batch.
    pub async fn send_front(&self) -> bool {
        let _one = self.sending.lock().await;
        let Some(mut entry) = self.prepare_front() else {
            return false;
        };
        let (u, m) = tokio::join!(
            self.work_kind(&entry, Kind::Usage),
            self.work_kind(&entry, Kind::Metering)
        );
        let unknown = self.apply(&mut entry, Kind::Usage, u) | self.apply(&mut entry, Kind::Metering, m);
        let now = now_ms();
        let since = entry.last_answer_ms.replace(now).unwrap_or(now);
        if unknown {
            // The bound runs only while the store's probes succeed: an outage is retried without
            // limit and never dead-lettered.
            let answering = now.saturating_sub(self.stamps.last_trip_ms.load(Ordering::Relaxed))
                <= STRICT_AGE_MS;
            if answering {
                entry.unknown_ms = entry.unknown_ms.saturating_add(now.saturating_sub(since));
                let lapsed = entry.unknown_ms > MAX_UNKNOWN.as_millis() as u64;
                let near_retention = now.saturating_sub(entry.batch.at_ms) > RETENTION_MARGIN_MS;
                if lapsed || near_retention {
                    self.dead_rest(
                        &mut entry,
                        DeadState::LandedUnknown,
                        "applied-unknown while the store answered other calls",
                    );
                }
            }
        }
        if entry.done() {
            return self.finish(entry);
        }
        self.put_back(entry);
        false
    }

    /// The front entry, after merging a never-sent run (capped) and recording `sent`.
    fn prepare_front(&self) -> Option<Entry> {
        let q = self.lock();
        let front = q.entries.front()?.clone();
        if front.sent {
            return Some(front);
        }
        // MERGE the contiguous run of never-sent batches at the front, in sequence order, up to the
        // caps. Split children are never in a never-sent batch, so they are never merged.
        let mut run: Vec<Entry> = Vec::new();
        let (mut cells, mut bytes) = (0usize, 0usize);
        for e in q.entries.iter().take_while(|e| !e.sent) {
            // The drop filters apply BEFORE merging, each by its own batch's sequence (a merged
            // batch carries the run's highest).
            let mut e = e.clone();
            let seq = e.batch.seq;
            e.batch.cells.retain(|c| !q.drops(&c.bucket, seq));
            e.batch.metering.retain(|r| !q.drops(&r.key_id, seq));
            let size = record::encode(&Rec::Batch(e.batch.clone())).len();
            if !run.is_empty()
                && (cells + e.batch.cells.len() > MERGE_MAX_CELLS || bytes + size > MERGE_MAX_BYTES)
            {
                break;
            }
            cells += e.batch.cells.len();
            bytes += size;
            run.push(e);
        }
        drop(q);
        let mut entry = if run.len() > 1 {
            let into = Batch {
                seq: run[run.len() - 1].batch.seq,
                usage_op: Op::mint(),
                metering_op: Op::mint(),
                cells: record::merged(run.iter().flat_map(|e| e.batch.cells.iter())),
                metering: run
                    .iter()
                    .flat_map(|e| e.batch.metering.iter().cloned())
                    .collect(),
                at_ms: run.iter().map(|e| e.batch.at_ms).min().unwrap_or_else(now_ms),
            };
            let seqs: Vec<u64> = run.iter().map(|e| e.batch.seq).collect();
            if self.spool(&[Rec::Merge { seqs, into: into.clone() }]).is_err() {
                // Not durable: send the front alone rather than an op no record vouches for.
                front
            } else {
                self.stats.merges.fetch_add(1, Ordering::Relaxed);
                let mut q = self.lock();
                for _ in 0..run.len() {
                    q.entries.pop_front();
                }
                q.entries.push_front(Entry::new(into.clone()));
                Entry::new(into)
            }
        } else {
            front
        };
        // `sent` is synced before the first send.
        if let Err(e) = self.spool(&[Rec::Sent { seq: entry.batch.seq }]) {
            tracing::error!(error = %e, "money spool: a `sent` record could not be synced; sending anyway (the batch replays under its own ops)");
        }
        entry.sent = true;
        if let Some(f) = self.lock().entries.front_mut() {
            f.sent = true;
        }
        Some(entry)
    }

    fn put_back(&self, entry: Entry) {
        let mut q = self.lock();
        if let Some(f) = q.entries.front_mut() {
            if f.batch.seq == entry.batch.seq {
                *f = entry;
            }
        }
    }

    fn finish(&self, entry: Entry) -> bool {
        {
            let mut q = self.lock();
            if q.entries.front().is_some_and(|f| f.batch.seq == entry.batch.seq) {
                q.entries.pop_front();
            }
        }
        self.ledger.landed(&entry.batch.cells, entry.batch.seq);
        self.restamp();
        true
    }

    /// The usage body of `cells` of batch `seq`, without dropped buckets.
    fn usage_of(&self, seq: u64, cells: &[CellCount]) -> Vec<(String, u64, UsageDelta)> {
        let q = self.lock();
        let kept: Vec<&CellCount> = cells.iter().filter(|c| !q.drops(&c.bucket, seq)).collect();
        drop(q);
        record::usage_body(kept)
    }

    fn metering_of(&self, seq: u64, rows: &[MeteringDelta]) -> Vec<MeteringDelta> {
        let q = self.lock();
        rows.iter()
            .filter(|r| !q.drops(&r.key_id, seq))
            .cloned()
            .collect()
    }

    /// Send `kind`'s whole op, or its undone parts one at a time.
    async fn work_kind(&self, entry: &Entry, kind: Kind) -> KindWork {
        match &match kind {
            Kind::Usage => entry.usage.clone(),
            Kind::Metering => entry.metering.clone(),
        } {
            KindState::Done => KindWork::Unchanged,
            KindState::Pending => {
                let out = self.post(entry, kind, entry.op(kind), 0, entry.len(kind)).await;
                KindWork::Whole(out)
            }
            KindState::Parts(parts) => {
                let mut outs = Vec::new();
                for (part, done) in parts {
                    if *done {
                        continue;
                    }
                    let out = self.post(entry, kind, part.op, part.lo, part.hi).await;
                    let stop = matches!(out, Outcome::Unknown(_) | Outcome::NotApplied);
                    outs.push((*part, out));
                    if stop {
                        break; // replay this part first: one in flight
                    }
                }
                KindWork::Parts(outs)
            }
        }
    }

    async fn post(&self, entry: &Entry, kind: Kind, op: Op, lo: usize, hi: usize) -> Outcome {
        self.stats.sends.fetch_add(1, Ordering::Relaxed);
        let seq = entry.batch.seq;
        let res = match kind {
            Kind::Usage => {
                let body = self.usage_of(seq, entry.batch.cells.get(lo..hi).unwrap_or_default());
                if body.is_empty() {
                    Ok(())
                } else {
                    self.store.add_usage_batch(op, &body).await
                }
            }
            Kind::Metering => {
                let body = self.metering_of(seq, entry.batch.metering.get(lo..hi).unwrap_or_default());
                if body.is_empty() {
                    Ok(())
                } else {
                    self.store.add_metering_batch(op, &body).await
                }
            }
        };
        let out = match res {
            Ok(()) => Outcome::Applied,
            Err(StoreFailure::Conflict) => {
                tracing::warn!(op = %op, "money: the store already recorded this op id with a body it renders differently; counted as applied");
                Outcome::Applied
            }
            Err(StoreFailure::Refused(t)) => Outcome::Refused(t),
            Err(StoreFailure::Overloaded) => Outcome::NotApplied,
            Err(StoreFailure::Failed(t) | StoreFailure::Fault(t)) => Outcome::Unknown(t),
        };
        if matches!(out, Outcome::Applied | Outcome::Refused(_)) {
            self.stamps.tripped(now_ms());
        }
        if matches!(out, Outcome::Unknown(_) | Outcome::NotApplied) {
            self.stats.replays.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(out, Outcome::Refused(_)) {
            self.stats.refusals.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    /// Apply `kind`'s answers to `entry`. Answers whether an op is still applied-unknown.
    fn apply(&self, entry: &mut Entry, kind: Kind, work: KindWork) -> bool {
        let mut parts = match entry.kind(kind).clone() {
            KindState::Parts(p) => p,
            KindState::Pending => vec![(
                Part {
                    op: entry.op(kind),
                    lo: 0,
                    hi: entry.len(kind),
                },
                false,
            )],
            KindState::Done => return false,
        };
        let outs = match work {
            KindWork::Unchanged => return false,
            KindWork::Whole(out) => vec![(parts[0].0, out)],
            KindWork::Parts(outs) => outs,
        };
        let mut unknown = false;
        let mut split = false;
        for (part, out) in outs {
            let Some(at) = parts.iter().position(|(p, _)| p.op == part.op) else {
                continue;
            };
            match out {
                Outcome::Applied => {
                    // A READY needs no `fsync` of its own: lost, the op replays and dedupes.
                    let _ = self.spool(&[Rec::Ready { op: part.op }]);
                    parts[at].1 = true;
                }
                Outcome::Refused(why) if part.hi - part.lo <= 1 => {
                    self.dead_range(entry, kind, (part.lo, part.hi), DeadState::Refused, &why);
                    parts[at].1 = true;
                }
                Outcome::Refused(_) => {
                    // BISECT: two halves, each under a new op.
                    let mid = part.lo + (part.hi - part.lo) / 2;
                    let halves = [
                        (Part { op: Op::mint(), lo: part.lo, hi: mid }, false),
                        (Part { op: Op::mint(), lo: mid, hi: part.hi }, false),
                    ];
                    parts.splice(at..=at, halves);
                    split = true;
                }
                Outcome::NotApplied => {}
                Outcome::Unknown(_) => unknown = true,
            }
        }
        if split {
            let rec = Rec::Split {
                seq: entry.batch.seq,
                kind,
                parts: parts.iter().map(|(p, _)| *p).collect(),
            };
            if self.spool(&[rec]).is_err() {
                // The halves are not durable: keep the refused op as it stood; it is re-sent and
                // refused again rather than sending parts no record vouches for.
                return unknown;
            }
        }
        *entry.kind(kind) = if parts.iter().all(|(_, d)| *d) {
            KindState::Done
        } else {
            KindState::Parts(parts)
        };
        unknown
    }

    /// Dead-letter every undone part of `entry` as `state`.
    fn dead_rest(&self, entry: &mut Entry, state: DeadState, why: &str) {
        for kind in [Kind::Usage, Kind::Metering] {
            let ranges: Vec<(usize, usize)> = match entry.kind(kind).clone() {
                KindState::Done => continue,
                KindState::Pending => vec![(0, entry.len(kind))],
                KindState::Parts(parts) => parts
                    .iter()
                    .filter(|(_, d)| !*d)
                    .map(|(p, _)| (p.lo, p.hi))
                    .collect(),
            };
            for r in ranges {
                self.dead_range(entry, kind, r, state, why);
            }
            *entry.kind(kind) = KindState::Done;
        }
    }

    /// DEAD-LETTER cells (or rows) `lo..hi` of `entry`'s `kind` body: counts to the dead-letter file,
    /// a synced spool `dead` record, an alarm. A `refused` letter's cells leave `posted_hi` and
    /// absorb later deltas of their `(bucket, window)`; never-sent batches carrying them are
    /// rewritten without them.
    fn dead_range(&self, entry: &Entry, kind: Kind, (lo, hi): (usize, usize), state: DeadState, why: &str) {
        let (cells, metering): (Vec<CellCount>, Vec<MeteringDelta>) = match kind {
            Kind::Usage => (entry.batch.cells.get(lo..hi).unwrap_or_default().to_vec(), Vec::new()),
            Kind::Metering => (Vec::new(), entry.batch.metering.get(lo..hi).unwrap_or_default().to_vec()),
        };
        let letter = {
            let mut q = self.lock();
            let id = q.next_dead;
            q.next_dead += 1;
            let letter = DeadLetter {
                id,
                kind,
                state,
                reason: why.to_string(),
                cells,
                metering,
                at_ms: now_ms(),
            };
            q.dead.push(letter.clone());
            letter
        };
        tracing::error!(seq = entry.batch.seq, kind = ?kind, state = ?state, reason = %why,
            buckets = ?letter.cells.iter().map(|c| c.bucket.as_str()).collect::<Vec<_>>(),
            "money: counts were dead-lettered; they await an operator's verdict");
        self.dead_append(&DeadRec::Letter(letter.clone()));
        let _ = self.spool(&[Rec::Dead { seq: entry.batch.seq, kind, lo, hi }]);
        if state == DeadState::Refused && !letter.cells.is_empty() {
            self.ledger.unposted(&letter.cells);
            self.rewrite_unsent(&letter);
        }
    }

    /// Every NEVER-SENT queued batch carrying one of `letter`'s `(bucket, window)` cells is
    /// rewritten without it, under a fresh op pair (its ops never left the node), with a synced,
    /// audited `rewrite` record. The removed counts fold into the letter.
    fn rewrite_unsent(&self, letter: &DeadLetter) {
        let keys: BTreeSet<(String, u64)> =
            letter.cells.iter().map(|c| (c.bucket.clone(), c.window)).collect();
        let mut rewrites: Vec<(Batch, Vec<CellCount>)> = Vec::new();
        let updated = {
            let mut q = self.lock();
            for e in q.entries.iter_mut().filter(|e| !e.sent) {
                let (gone, kept): (Vec<CellCount>, Vec<CellCount>) =
                    std::mem::take(&mut e.batch.cells)
                        .into_iter()
                        .partition(|c| keys.contains(&(c.bucket.clone(), c.window)));
                e.batch.cells = kept;
                if gone.is_empty() {
                    continue;
                }
                e.batch.usage_op = Op::mint();
                e.batch.metering_op = Op::mint();
                if e.batch.cells.is_empty() {
                    e.usage = KindState::Done;
                }
                rewrites.push((e.batch.clone(), gone));
            }
            let at = q.dead.iter().position(|d| d.id == letter.id);
            if let Some(i) = at {
                for (_, gone) in &rewrites {
                    for c in gone {
                        let l = &mut q.dead[i];
                        match l.cells.iter_mut().find(|d| d.bucket == c.bucket && d.window == c.window) {
                            Some(d) => d.merge(c),
                            None => l.cells.push(c.clone()),
                        }
                    }
                }
            }
            at.map(|i| q.dead[i].clone())
        };
        for (batch, gone) in rewrites {
            tracing::warn!(seq = batch.seq, cells = gone.len(),
                "money audit: a never-sent batch was rewritten without dead-lettered cells, under fresh op ids");
            self.ledger.unposted(&gone);
            let _ = self.spool(&[Rec::Rewrite { into: batch }]);
        }
        if let Some(l) = updated {
            self.dead_append(&DeadRec::Letter(l));
        }
    }

    /// `bucket` is about to be deleted from the store: a synced `drop(bucket, seq)` record, written
    /// BEFORE the store deletes it. Every batch up to the next take's sequence leaves its cells
    /// out, on its first send and every replay; later batches (a re-created bucket) keep theirs.
    pub fn drop_bucket(&self, bucket: &str) {
        let seq = {
            let mut q = self.lock();
            let seq = q.next_seq;
            q.dropped.push((bucket.to_string(), seq));
            seq
        };
        if let Err(e) = self.spool(&[Rec::Drop { bucket: bucket.to_string(), seq }]) {
            tracing::error!(error = %e, bucket, "money spool: a bucket drop could not be synced");
        }
    }

    /// THE OPERATOR'S CLEAR of dead letter `id` (audited by the caller): `Landed` drops a
    /// `landed-unknown` letter; `Repost` re-posts it under a NEW op id, the `reposted` record synced
    /// before the send.
    ///
    /// # Errors
    ///
    /// No such letter, `Landed` on a `refused` letter, or the re-post did not land.
    pub async fn clear(&self, id: u64, verdict: Verdict) -> Result<DeadLetter, String> {
        let letter = self
            .lock()
            .dead
            .iter()
            .find(|d| d.id == id)
            .cloned()
            .ok_or_else(|| format!("no dead letter {id}"))?;
        match verdict {
            Verdict::Landed if letter.state == DeadState::Refused => {
                return Err("a refused dead letter never landed: re-post it".to_string());
            }
            Verdict::Landed => {
                self.dead_append(&DeadRec::Cleared { id });
            }
            Verdict::Repost => {
                let (u, m) = (Op::mint(), Op::mint());
                self.dead_append(&DeadRec::Reposted { id, op: u });
                let landed = |r: Result<(), StoreFailure>| match r {
                    Ok(()) | Err(StoreFailure::Conflict) => Ok(()),
                    Err(e) => Err(e.to_string()),
                };
                if !letter.cells.is_empty() {
                    let body = record::usage_body(&letter.cells);
                    landed(self.store.add_usage_batch(u, &body).await)?;
                }
                if !letter.metering.is_empty() {
                    landed(self.store.add_metering_batch(m, &letter.metering).await)?;
                }
                self.stamps.tripped(now_ms());
                if letter.state == DeadState::Refused {
                    // Now in the store: back into `posted_hi`.
                    self.ledger.reposted(&letter.cells);
                }
                self.dead_append(&DeadRec::Cleared { id });
            }
        }
        self.lock().dead.retain(|d| d.id != id);
        Ok(letter)
    }

    /// DELIVER what is queued (and, at shutdown, what is pending), until nothing is left or
    /// `deadline` passes. Answers whether everything was delivered.
    pub async fn drain(&self, take_pending: bool, deadline: Duration) -> bool {
        let mut until = tokio::time::Instant::now() + deadline;
        let mut refusals = self.stats.refusals.load(Ordering::Relaxed);
        if take_pending {
            self.take_once();
        }
        loop {
            if self.unresolved() == 0 {
                return true;
            }
            // Every refusal met extends the deadline: bisecting costs round trips.
            let met = self.stats.refusals.load(Ordering::Relaxed);
            if met > refusals {
                let more = u32::try_from(met - refusals).unwrap_or(u32::MAX);
                until += REPLAY_PER_REFUSAL * more;
                refusals = met;
            }
            if tokio::time::Instant::now() >= until {
                tracing::error!(
                    unresolved = self.unresolved(),
                    "money: batches were still undelivered to the store at the deadline"
                );
                return false;
            }
            if !self.send_front().await {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(REPLAY_PAUSE.min(left)).await;
            }
        }
    }

    async fn probe_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(PROBE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let last = self.stamps.last_trip_ms.load(Ordering::Relaxed);
            if now_ms().saturating_sub(last) < PROBE_EVERY.as_millis() as u64 {
                continue;
            }
            if self.store.probe().await.is_ok() {
                self.stamps.tripped(now_ms());
            }
        }
    }
}

#[derive(Debug)]
enum Outcome {
    Applied,
    Refused(String),
    NotApplied,
    Unknown(String),
}

#[derive(Debug)]
enum KindWork {
    Unchanged,
    Whole(Outcome),
    Parts(Vec<(Part, Outcome)>),
}

/// A take's cells and rows as batches of at most [`MERGE_MAX_CELLS`] cells (or rows) and about
/// [`MERGE_MAX_BYTES`] each, in order.
fn chunked(
    cells: Vec<CellCount>,
    metering: Vec<MeteringDelta>,
) -> Vec<(Vec<CellCount>, Vec<MeteringDelta>)> {
    fn size<T: Serialize>(t: &T) -> usize {
        serde_json::to_vec(t).map(|v| v.len()).unwrap_or(0)
    }
    let mut out: Vec<(Vec<CellCount>, Vec<MeteringDelta>)> = vec![(Vec::new(), Vec::new())];
    let mut bytes = 0usize;
    let mut room = |out: &mut Vec<(Vec<CellCount>, Vec<MeteringDelta>)>, add: usize| {
        let last = out.last().expect("one chunk");
        let n = last.0.len().max(last.1.len());
        if n > 0 && (n >= MERGE_MAX_CELLS || bytes + add > MERGE_MAX_BYTES) {
            out.push((Vec::new(), Vec::new()));
            bytes = 0;
        }
        bytes += add;
    };
    for c in cells {
        room(&mut out, size(&c));
        out.last_mut().expect("one chunk").0.push(c);
    }
    for r in metering {
        room(&mut out, size(&r));
        out.last_mut().expect("one chunk").1.push(r);
    }
    out.retain(|(c, m)| !c.is_empty() || !m.is_empty());
    out
}

/// Fold the spool's records into the queue.
fn fold(q: &mut Queue, recs: Vec<Rec>) {
    let mut ready: BTreeSet<Op> = BTreeSet::new();
    let mut entries: BTreeMap<u64, Entry> = BTreeMap::new();
    let mut dead: Vec<(u64, Kind, usize, usize)> = Vec::new();
    for r in recs {
        match r {
            Rec::Batch(b) => {
                q.next_seq = q.next_seq.max(b.seq + 1);
                entries.insert(b.seq, Entry::new(b));
            }
            Rec::Sent { seq } => {
                if let Some(e) = entries.get_mut(&seq) {
                    e.sent = true;
                }
            }
            Rec::Merge { seqs, into } => {
                for s in &seqs {
                    entries.remove(s);
                }
                q.next_seq = q.next_seq.max(into.seq + 1);
                entries.insert(into.seq, Entry::new(into));
            }
            Rec::Ready { op } => {
                ready.insert(op);
            }
            Rec::Split { seq, kind, parts } => {
                if let Some(e) = entries.get_mut(&seq) {
                    *e.kind(kind) = KindState::Parts(parts.into_iter().map(|p| (p, false)).collect());
                }
            }
            Rec::Dead { seq, kind, lo, hi } => dead.push((seq, kind, lo, hi)),
            Rec::Rewrite { into } => {
                if let Some(e) = entries.get_mut(&into.seq) {
                    let sent = e.sent;
                    *e = Entry::new(into);
                    e.sent = sent;
                }
            }
            Rec::Drop { bucket, seq } => {
                q.next_seq = q.next_seq.max(seq);
                q.dropped.push((bucket, seq));
            }
        }
    }
    for e in entries.values_mut() {
        let seq = e.batch.seq;
        for kind in [Kind::Usage, Kind::Metering] {
            let (op, len) = (e.op(kind), e.len(kind));
            let st = e.kind(kind);
            let is_dead = |lo: usize, hi: usize| {
                dead.iter()
                    .any(|d| d.0 == seq && d.1 == kind && d.2 == lo && d.3 == hi)
            };
            match st {
                KindState::Pending if ready.contains(&op) || is_dead(0, len) => {
                    *st = KindState::Done;
                }
                KindState::Parts(parts) => {
                    for (p, done) in parts.iter_mut() {
                        if ready.contains(&p.op) || is_dead(p.lo, p.hi) {
                            *done = true;
                        }
                    }
                    if parts.iter().all(|(_, d)| *d) {
                        *st = KindState::Done;
                    }
                }
                _ => {}
            }
        }
    }
    q.entries = entries.into_values().filter(|e| !e.done()).collect();
}

#[cfg(test)]
#[path = "tests/recorder_tests.rs"]
mod tests;
