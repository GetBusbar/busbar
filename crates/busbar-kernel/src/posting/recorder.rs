// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDER: counts reach the store OFF the request path (MONEY-DESIGN §3c, OWNER RULING
//! 2026-10-25: "Stores need to not be in the hot path; latency is crucial").
//!
//! - The request path only emits deltas into its budget shard's pending map ([`Ledger`]).
//! - THE SPOOL WRITER is one OS thread of its own, fed by a std channel, and the only owner of the
//!   UNSENT ACCUMULATOR (one entry per cell: a sum, so a cell's `+1` and `-1` net out). Every flush
//!   window it takes the pending maps one shard at a time, adds the take into the accumulator and,
//!   with a data directory, writes ONE synced `fold` record carrying it together with every record
//!   queued since. No runtime thread ever waits on a disk.
//! - THE SENDER (a task) ASKS the writer for a batch: the writer CARVES up to the cap out of the
//!   accumulator (each cell's whole net), under a new SEQUENCE and two op ids, with ONE synced
//!   `carve` record that consumes the cells and records them sent, and hands back the sealed body.
//!   The sender resolves the lowest unresolved sequence first, exactly ONE in flight, so a refund's
//!   `-1` never lands before the `+1` it cancels.
//! - THE HEARTBEAT (a task) writes an idempotent per-node record every second while work is
//!   unresolved or strict mode is on ([`PostStore::heartbeat`], one seam).
//!
//! What an answer proves (S5), per op: READY applied; Conflict on a spooled op applied (alarmed);
//! REFUSED nothing applied, so that op is BISECTED and a single cell refused alone is
//! dead-lettered; Overloaded not applied, retried; anything else applied-unknown, replayed with the
//! identical body under the same op id, without limit while the heartbeat fails and for 10 minutes
//! of a SUCCEEDING heartbeat at most, then dead-lettered `landed-unknown`; a carve unresolved 24 h
//! after it was sent is dead-lettered, never replayed.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, RecordStore, UsageDelta, UsageLedger};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use serde::{Deserialize, Serialize};

use super::record::{self, Batch, CellCount, DeadState, Kind, Op, Part, Rec};
use super::spool::{self, Ledgerette, Spool};

/// Strict mode refuses when an age passes this.
pub const STRICT_AGE_MS: u64 = 2_000;

/// The heartbeat's cadence.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);

/// Boot replay's base deadline: past it (and its extensions) the boot fails, as hydrate's store
/// error does.
pub const REPLAY_DEADLINE: Duration = Duration::from_secs(120);

/// Each refusal met during boot replay extends its deadline by this.
pub const REPLAY_PER_REFUSAL: Duration = Duration::from_secs(30);

/// A carve unresolved this long after it was sent is dead-lettered `landed-unknown`, never
/// replayed: the contract forbids re-issuing an op id past its retention.
pub const RETENTION_MS: u64 = OP_ID_RETENTION_SECS * 1_000;

/// An op applied-unknown for this long WHILE THE HEARTBEAT SUCCEEDS is dead-lettered
/// `landed-unknown`. While the heartbeat fails it is retried with backoff without limit.
pub const MAX_UNKNOWN: Duration = Duration::from_secs(10 * 60);

/// A carve takes at most this many cells (or metering rows) ...
pub const CARVE_MAX_CELLS: usize = 4_096;

/// ... and at most about this many encoded bytes.
pub const CARVE_MAX_BYTES: usize = 256 * 1024;

/// The spool is compacted when nothing is carved and unresolved and it is past this size ...
const COMPACT_BYTES: u64 = 4 * 1024 * 1024;

/// ... and alarmed when it is past this one.
const ALARM_BYTES: u64 = 256 * 1024 * 1024;

/// The unsent accumulator is alarmed past this many cells (RAM high-water).
const ACC_ALARM_CELLS: usize = 1_000_000;

/// The pause before an unresolved op is replayed.
const REPLAY_PAUSE: Duration = Duration::from_millis(200);

/// The schema of the heartbeat record (an idempotent per-node write; owner item 32).
pub const HEARTBEAT_SCHEMA: &str = "busbar.node.heartbeat.v1";

fn now_ms() -> u64 {
    crate::store::now_ms()
}

// ── the seams ────────────────────────────────────────────────────────────────────────────────────

/// What the recorder takes from and reports to: the governance book.
pub trait Ledger: Send + Sync {
    /// Every shard's pending deltas, taken one shard at a time (their positive parts join
    /// `posted_hi` as they are taken). `mark` is called with each taken bucket INSIDE its shard's
    /// critical section (lock order: shard, then the unrecorded set), so the sweep never sees a
    /// cell whose deltas are in neither the pending map nor the unrecorded set.
    fn take_pending(&self, mark: &dyn Fn(&str)) -> Vec<CellCount>;
    /// The pending metering rows.
    fn take_metering(&self) -> Vec<MeteringDelta>;
    /// `cells` answered READY (or were dead-lettered `landed-unknown`): their negative parts join
    /// `posted_hi`.
    fn landed(&self, cells: &[CellCount]);
    /// `cells` will never reach the store (dead-lettered `refused`): their positive parts leave
    /// `posted_hi`.
    fn unposted(&self, cells: &[CellCount]);
    /// A cleared letter's `cells` were re-posted and answered READY.
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
    /// THE HEARTBEAT: a write proving the store takes writes (owner item 32: a per-node record, or
    /// an empty `add_usage_batch`).
    fn heartbeat(&self) -> StoreCall<'_, ()>;
    /// `get_usage` of one row.
    fn get_usage<'a>(&'a self, bucket: &'a str, window: u64) -> StoreCall<'a, UsageLedger>;
}

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

    fn heartbeat(&self) -> StoreCall<'_, ()> {
        Box::pin(async move {
            let key = crate::door::node().to_be_bytes();
            let value = RecordBytes::new(now_ms().to_be_bytes().to_vec())
                .map_err(|n| StoreFailure::Fault(format!("a heartbeat of {n} bytes")))?;
            self.calls.record_put(HEARTBEAT_SCHEMA, &key, &value).await
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

    fn heartbeat(&self) -> StoreCall<'_, ()> {
        let records = Arc::clone(&self.0);
        blocking(move || records.get_usage("e:heartbeat", 0).map(|_| ()))
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
    /// Unrecorded work has made no progress to READY for 2 s.
    Undelivered,
    /// A capped bucket's last fleet snapshot read failed more than 5 s ago.
    SnapshotStale,
}

impl Closed {
    /// The explanation the 503 and its audit record carry.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Closed::Undelivered => {
                "spend recorded on this node has not reached the store for over 2 s"
            }
            Closed::SnapshotStale => {
                "the fleet's spend for a capped bucket could not be read for over 5 s"
            }
        }
    }
}

/// SHARED STAMPS: written by the spool writer, the sender and the heartbeat; read by the admission
/// path without asking them, so a dead task cannot leave strict mode open.
#[derive(Debug)]
pub struct Stamps {
    /// The last heartbeat that succeeded (the landed-unknown bound runs only while it does).
    heartbeat_ok_ms: AtomicU64,
    /// Whether unrecorded work exists (accumulator or unresolved carves; dead letters excluded).
    working: AtomicBool,
    /// The last progress toward READY (a READY, a resolved part, or work appearing).
    progress_ms: AtomicU64,
    /// Strict mode is on: the heartbeat writes even while idle.
    strict: AtomicBool,
    /// THE UNRECORDED SET: buckets with deltas in the accumulator or in an unresolved carve. A cell
    /// in it (or with pending deltas) is never evicted by the sweep.
    unrecorded: RwLock<HashSet<String>>,
}

impl Stamps {
    fn new() -> Self {
        let now = now_ms();
        Stamps {
            heartbeat_ok_ms: AtomicU64::new(now),
            working: AtomicBool::new(false),
            progress_ms: AtomicU64::new(now),
            strict: AtomicBool::new(false),
            unrecorded: RwLock::new(HashSet::new()),
        }
    }

    fn progressed(&self, at_ms: u64) {
        self.progress_ms.fetch_max(at_ms, Ordering::Relaxed);
    }

    fn heartbeat_ok(&self, now: u64) -> bool {
        now.saturating_sub(self.heartbeat_ok_ms.load(Ordering::Relaxed)) <= STRICT_AGE_MS
    }

    /// Strict mode on or off (the heartbeat writes while idle only when on).
    pub fn set_strict(&self, on: bool) {
        self.strict.store(on, Ordering::Relaxed);
    }

    /// Whether `bucket` has unrecorded deltas (the sweep keeps its cell).
    #[must_use]
    pub fn unrecorded(&self, bucket: &str) -> bool {
        self.unrecorded
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(bucket)
    }

    /// Whether spend can be recorded at `now_ms`, from the stamps alone.
    ///
    /// # Errors
    ///
    /// Why it cannot.
    pub fn check(&self, now_ms: u64) -> Result<(), Closed> {
        // ONE age rule (the other is the fleet snapshot's, per bucket): 2 s of no recording
        // progress while there is unrecorded work. Dead letters are not work; a bisect is progress.
        if self.working.load(Ordering::Relaxed)
            && now_ms.saturating_sub(self.progress_ms.load(Ordering::Relaxed)) > STRICT_AGE_MS
        {
            return Err(Closed::Undelivered);
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
    /// Its usage cells. Every later delta of the same `(bucket, window)` folds in while a
    /// `refused` letter stands.
    #[serde(default)]
    pub cells: Vec<CellCount>,
    /// The later NEGATIVE deltas a `landed-unknown` letter absorbed: posted on either verdict.
    #[serde(default)]
    pub absorbed: Vec<CellCount>,
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
    /// The operator's verdict, written before any re-post (`landed: false` re-posts).
    Verdict { id: u64, landed: bool },
    /// Gone: its re-posts answered READY.
    Cleared { id: u64 },
}

/// The operator's verdict on a dead letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A `landed-unknown` letter did land: only its absorbed negatives are posted.
    Landed,
    /// It did not land (or was `refused`): re-post it, then its absorbed negatives.
    NotLanded,
}

// ── the accumulator and the carves ───────────────────────────────────────────────────────────────

/// A metering row's key in the accumulator.
type MeterKey = (String, u64, String, String, u64);

fn meter_key(r: &MeteringDelta) -> MeterKey {
    (
        r.key_id.clone(),
        r.bucket,
        r.model.clone(),
        r.provider.clone(),
        r.priced_from_ms,
    )
}

fn meter_add(into: &mut MeteringDelta, r: &MeteringDelta, sign: bool) {
    let f = |a: u64, b: u64| {
        if sign {
            a.saturating_add(b)
        } else {
            a.saturating_sub(b)
        }
    };
    into.requests = f(into.requests, r.requests);
    into.billable_requests = f(into.billable_requests, r.billable_requests);
    into.tokens_input = f(into.tokens_input, r.tokens_input);
    into.tokens_output = f(into.tokens_output, r.tokens_output);
    into.tokens_cache_read = f(into.tokens_cache_read, r.tokens_cache_read);
    into.tokens_cache_write = f(into.tokens_cache_write, r.tokens_cache_write);
    for (k, n) in &r.usage_units {
        let slot = into.usage_units.entry(k.clone()).or_insert(0);
        *slot = f(*slot, *n);
    }
    into.usage_units.retain(|_, n| *n != 0);
}

fn meter_zero(r: &MeteringDelta) -> bool {
    r.requests == 0
        && r.tokens_input == 0
        && r.tokens_output == 0
        && r.tokens_cache_read == 0
        && r.tokens_cache_write == 0
        && r.usage_units.is_empty()
}

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
    usage: KindState,
    metering: KindState,
    /// How long it has been applied-unknown while the heartbeat succeeded, ms (this boot).
    unknown_ms: u64,
    /// The last answer's time, wall-clock ms (this boot).
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

/// The state the writer thread and the sender share (short holds, never across I/O).
#[derive(Default)]
struct Core {
    /// THE UNSENT ACCUMULATOR, usage: one net cell per (bucket, window).
    acc: BTreeMap<(String, u64), CellCount>,
    /// THE UNSENT ACCUMULATOR, metering: one row per key.
    acc_meter: BTreeMap<MeterKey, MeteringDelta>,
    /// Carves not yet resolved, in sequence order.
    entries: VecDeque<Entry>,
    next_seq: u64,
    window_seq: u64,
    dead: Vec<DeadLetter>,
    next_dead: u64,
    /// Ops whose first applied-unknown answer is recorded.
    failing: BTreeMap<Op, u64>,
    /// The accumulator's high-water alarm is raised.
    alarmed: bool,
}

impl Core {
    fn add_cells(&mut self, cells: &[CellCount], sign: bool) {
        for c in cells {
            let key = (c.bucket.clone(), c.window);
            let add = if sign { c.clone() } else { c.negated() };
            let slot = self
                .acc
                .entry(key.clone())
                .or_insert_with(|| CellCount::new(&c.bucket, c.window));
            slot.merge(&add);
            if slot.is_zero() {
                self.acc.remove(&key);
            }
        }
    }

    fn add_rows(&mut self, rows: &[MeteringDelta], sign: bool) {
        for r in rows {
            let key = meter_key(r);
            match self.acc_meter.get_mut(&key) {
                Some(into) => {
                    meter_add(into, r, sign);
                    if meter_zero(into) {
                        self.acc_meter.remove(&key);
                    }
                }
                None if sign => {
                    self.acc_meter.insert(key, r.clone());
                }
                None => {}
            }
        }
    }

    /// The standing letter absorbing a later `(bucket, window)` delta: a `refused` letter takes it
    /// whole; a `landed-unknown` one only its negative part (`negative`).
    fn absorbing(&self, bucket: &str, window: u64, negative: bool) -> Option<usize> {
        self.dead.iter().position(|d| {
            (d.state == DeadState::Refused || negative)
                && d.kind == Kind::Usage
                && d.cells.iter().any(|c| c.bucket == bucket && c.window == window)
        })
    }

    /// CARVE up to the cap out of the accumulator, in its stable order, each cell's whole net.
    fn carve(&mut self) -> Option<Batch> {
        if self.acc.is_empty() && self.acc_meter.is_empty() {
            return None;
        }
        let mut bytes = 0usize;
        let mut cells = Vec::new();
        let keys: Vec<(String, u64)> = self.acc.keys().cloned().collect();
        for k in keys {
            let size = serde_json::to_vec(&self.acc[&k]).map(|v| v.len()).unwrap_or(0);
            if !cells.is_empty() && (cells.len() >= CARVE_MAX_CELLS || bytes + size > CARVE_MAX_BYTES)
            {
                break;
            }
            bytes += size;
            cells.push(self.acc.remove(&k).expect("listed"));
        }
        let mut metering = Vec::new();
        let keys: Vec<MeterKey> = self.acc_meter.keys().cloned().collect();
        for k in keys {
            let size = serde_json::to_vec(&self.acc_meter[&k])
                .map(|v| v.len())
                .unwrap_or(0);
            if !(cells.is_empty() && metering.is_empty())
                && (metering.len() >= CARVE_MAX_CELLS || bytes + size > CARVE_MAX_BYTES)
            {
                break;
            }
            bytes += size;
            metering.push(self.acc_meter.remove(&k).expect("listed"));
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        Some(Batch {
            seq,
            usage_op: Op::mint(),
            metering_op: Op::mint(),
            cells,
            metering,
            t_sent: now_ms(),
        })
    }

    fn unrecorded(&self) -> HashSet<String> {
        self.acc
            .keys()
            .map(|(b, _)| b.clone())
            .chain(
                self.entries
                    .iter()
                    .flat_map(|e| e.batch.cells.iter().map(|c| c.bucket.clone())),
            )
            .collect()
    }

    fn working(&self) -> bool {
        !self.acc.is_empty() || !self.acc_meter.is_empty() || !self.entries.is_empty()
    }
}

/// Where the recorder keeps its records.
#[derive(Debug, Clone)]
pub enum Medium {
    /// A data directory: the spool and the dead-letter file live under it.
    Dir(PathBuf),
    /// No data directory: RAM.
    Memory,
}

/// Counters a test reads.
#[derive(Debug, Default)]
pub struct Stats {
    /// Takes that folded something.
    pub folds: AtomicU64,
    /// Carves.
    pub carves: AtomicU64,
    /// Store sends (first sends and replays, whole ops and parts).
    pub sends: AtomicU64,
    /// Replays of an unresolved op.
    pub replays: AtomicU64,
    /// REFUSED answers met.
    pub refusals: AtomicU64,
    /// Spool `fsync`s (0 without a data directory).
    pub fsyncs: AtomicU64,
    /// The OS thread the last `fsync` ran on (a test proves it is never a request thread).
    pub fsync_thread: Mutex<Option<std::thread::ThreadId>>,
}

/// How a writer round is acknowledged once durable.
enum Ack {
    Async(tokio::sync::oneshot::Sender<Result<(), String>>),
}

impl Ack {
    fn send(self, r: Result<(), String>) {
        match self {
            Ack::Async(tx) => {
                let _ = tx.send(r);
            }
        }
    }
}

enum WriterMsg {
    /// Records (and dead-letter records) for the next round.
    Write {
        recs: Vec<Rec>,
        dead: Vec<DeadRec>,
        ack: Ack,
    },
    /// Records that need no `fsync` of their own (READY, `failing`): they ride the next fold's.
    Lazy(Vec<Rec>),
    /// The sender asks for a batch.
    Carve(tokio::sync::oneshot::Sender<Option<Batch>>),
    /// Take now (a drain), then write.
    Take(Ack),
    /// Stop after this round; acknowledged once it is written.
    Stop(Ack),
}

/// THE RECORDER of one opened store.
pub struct Recorder {
    ledger: Arc<dyn Ledger>,
    store: Arc<dyn PostStore>,
    core: Mutex<Core>,
    stamps: Arc<Stamps>,
    stats: Arc<Stats>,
    writer: Mutex<mpsc::Sender<WriterMsg>>,
    wake_sender: tokio::sync::Notify,
    stopped: AtomicBool,
    /// Serializes the sender's work (the task and a boot or shutdown drain never interleave).
    sending: tokio::sync::Mutex<()>,
    spooled: bool,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("spooled", &self.spooled)
            .finish_non_exhaustive()
    }
}

/// What the spool and the dead-letter file held at open.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Unresolved carves to deliver before hydrate.
    pub carves: usize,
    /// Cells in the unsent accumulator and those carves (the replay deadline grows with them).
    pub cells: usize,
    /// The `refused` dead letters' cells: RAM `cur` counts them (never `posted_hi`). A
    /// `landed-unknown` letter is never added to `cur`.
    pub refused_cells: Vec<CellCount>,
}

impl Recovered {
    /// Boot replay's base deadline: 120 s, plus 2 s per 4,096 backlog cells (each refusal met
    /// extends it by 30 s more, as the replay runs).
    #[must_use]
    pub fn deadline(&self) -> Duration {
        let per = u64::try_from(self.cells.div_ceil(CARVE_MAX_CELLS)).unwrap_or(u64::MAX);
        REPLAY_DEADLINE + Duration::from_secs(per.saturating_mul(2))
    }

    /// Whether anything is to deliver.
    #[must_use]
    pub fn any(&self) -> bool {
        self.cells > 0 || self.carves > 0
    }
}

fn io_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl Recorder {
    /// A recorder over `store`, taking from `ledger` every `window`, keeping its records on
    /// `medium`, its spool writer started on an OS thread of its own. With a data directory the
    /// spool and dead letters are read back (an `ephemeral` store discards both first).
    ///
    /// # Errors
    ///
    /// The data directory could not be read or written, or the writer thread could not start.
    pub fn open(
        ledger: Arc<dyn Ledger>,
        store: Arc<dyn PostStore>,
        medium: &Medium,
        ephemeral: bool,
        window: Duration,
        syncer: Arc<dyn spool::Syncer>,
    ) -> Result<(Arc<Recorder>, Recovered), String> {
        let mut core = Core::default();
        let (spool, dead_file) = match medium {
            Medium::Dir(dir) => {
                let spool_dir = dir.join("money-spool");
                let dead = Ledgerette::at(spool_dir.join("DEADLETTERS"));
                if ephemeral {
                    Spool::discard(&spool_dir).map_err(io_err)?;
                    dead.discard().map_err(io_err)?;
                }
                let (s, recs) = Spool::open(&spool_dir, syncer).map_err(io_err)?;
                fold(&mut core, recs);
                for body in dead.read().map_err(io_err)? {
                    match serde_json::from_slice::<DeadRec>(&body) {
                        Ok(DeadRec::Letter(l)) => {
                            core.next_dead = core.next_dead.max(l.id + 1);
                            core.dead.retain(|d| d.id != l.id);
                            core.dead.push(l);
                        }
                        Ok(DeadRec::Cleared { id }) => core.dead.retain(|d| d.id != id),
                        Ok(DeadRec::Verdict { .. }) | Err(_) => {}
                    }
                }
                (Some(s), Some(dead))
            }
            Medium::Memory => (None, None),
        };
        let recovered = Recovered {
            carves: core.entries.len(),
            cells: core.acc.len()
                + core.acc_meter.len()
                + core
                    .entries
                    .iter()
                    .map(|e| e.batch.cells.len())
                    .sum::<usize>(),
            refused_cells: core
                .dead
                .iter()
                .filter(|d| d.state == DeadState::Refused)
                .flat_map(|d| d.cells.clone())
                .collect(),
        };
        let window_ms = u64::try_from(window.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let (tx, rx) = mpsc::channel();
        let stamps = Arc::new(Stamps::new());
        *stamps
            .unrecorded
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = core.unrecorded();
        stamps.working.store(core.working(), Ordering::Relaxed);
        let rec = Arc::new(Recorder {
            ledger,
            store,
            stamps,
            spooled: spool.is_some(),
            core: Mutex::new(core),
            stats: Arc::new(Stats::default()),
            writer: Mutex::new(tx),
            wake_sender: tokio::sync::Notify::new(),
            stopped: AtomicBool::new(false),
            sending: tokio::sync::Mutex::new(()),
        });
        let writer = Writer {
            rec: Arc::downgrade(&rec),
            rx,
            spool,
            dead_file,
            window: Duration::from_millis(window_ms),
        };
        std::thread::Builder::new()
            .name("busbar-spend-spool".to_string())
            .spawn(move || writer.run())
            .map_err(|e| format!("the spend spool writer thread could not start: {e}"))?;
        Ok((rec, recovered))
    }

    /// The shared stamps strict mode and the sweep read.
    #[must_use]
    pub fn stamps(&self) -> Arc<Stamps> {
        Arc::clone(&self.stamps)
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> Arc<dyn PostStore> {
        Arc::clone(&self.store)
    }

    /// Whether a data directory backs the recorder.
    #[must_use]
    pub fn spooled(&self) -> bool {
        self.spooled
    }

    /// Whether anything is unrecorded (accumulated or carved and unresolved).
    #[must_use]
    pub fn working(&self) -> bool {
        self.lock().working()
    }

    /// Carves not yet resolved.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.lock().entries.len()
    }

    /// The dead letters standing now.
    #[must_use]
    pub fn dead_letters(&self) -> Vec<DeadLetter> {
        self.lock().dead.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn post_msg(&self, msg: WriterMsg) -> bool {
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(msg)
            .is_ok()
    }

    /// Queue `recs` (and `dead`) for the writer's next round, and AWAIT its `fsync`.
    async fn sync(&self, recs: Vec<Rec>, dead: Vec<DeadRec>) -> Result<(), String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if !self.post_msg(WriterMsg::Write {
            recs,
            dead,
            ack: Ack::Async(tx),
        }) {
            return Err("the spend spool writer has stopped".to_string());
        }
        rx.await
            .unwrap_or_else(|_| Err("the spend spool writer has stopped".to_string()))
    }

    /// Queue `recs` without waiting (a READY needs no `fsync` of its own: lost, its op replays and
    /// dedupes).
    fn lazy(&self, recs: Vec<Rec>) {
        self.post_msg(WriterMsg::Lazy(recs));
    }

    /// Republish the unrecorded set and the work stamp.
    fn restamp(&self) {
        let (set, working) = {
            let core = self.lock();
            (core.unrecorded(), core.working())
        };
        *self
            .stamps
            .unrecorded
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = set;
        let was = self.stamps.working.swap(working, Ordering::Relaxed);
        if working && !was {
            self.stamps.progressed(now_ms());
        }
    }

    /// Start the sender and the heartbeat on the current runtime (the spool writer runs on its own
    /// thread from [`Recorder::open`]).
    pub fn spawn(self: &Arc<Self>) {
        let sender = Arc::clone(self);
        tokio::spawn(async move { sender.send_loop().await });
        let beat = Arc::clone(self);
        tokio::spawn(async move { beat.heartbeat_loop().await });
    }

    /// Stop the tasks and the writer thread, AWAITING the writer's last round.
    pub async fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake_sender.notify_one();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.post_msg(WriterMsg::Stop(Ack::Async(tx))) {
            let _ = rx.await;
        }
    }

    // ── the writer thread's work ───────────────────────────────────────────────────────────────

    /// ONE TAKE: the pending maps added into the accumulator (later deltas of a dead-lettered cell
    /// fold into its letter instead). Answers the `fold` record and the letters to write.
    fn take(&self) -> (Option<Rec>, Vec<DeadRec>) {
        let stamps = Arc::clone(&self.stamps);
        let mark = move |bucket: &str| {
            stamps
                .unrecorded
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(bucket.to_string());
        };
        let cells = self.ledger.take_pending(&mark);
        let metering = self.ledger.take_metering();
        let mut dead_recs = Vec::new();
        let mut unposted: Vec<CellCount> = Vec::new();
        let mut kept = Vec::new();
        let rec = {
            let mut core = self.lock();
            for c in record::merged(&cells) {
                let refused = core.absorbing(&c.bucket, c.window, false);
                let neg = c.signed_part(false);
                let landed = core.absorbing(&c.bucket, c.window, true);
                match (refused, landed) {
                    (Some(i), _) => {
                        let letter = &mut core.dead[i];
                        match letter
                            .cells
                            .iter_mut()
                            .find(|d| d.bucket == c.bucket && d.window == c.window)
                        {
                            Some(d) => d.merge(&c),
                            None => letter.cells.push(c.clone()),
                        }
                        unposted.push(c);
                        dead_recs.push(DeadRec::Letter(letter.clone()));
                    }
                    (None, Some(i)) if !neg.is_zero() => {
                        let mut neg = neg;
                        neg.bucket.clone_from(&c.bucket);
                        let letter = &mut core.dead[i];
                        match letter
                            .absorbed
                            .iter_mut()
                            .find(|d| d.bucket == neg.bucket && d.window == neg.window)
                        {
                            Some(d) => d.merge(&neg),
                            None => letter.absorbed.push(neg),
                        }
                        dead_recs.push(DeadRec::Letter(letter.clone()));
                        let mut pos = c.signed_part(true);
                        pos.bucket.clone_from(&c.bucket);
                        if !pos.is_zero() {
                            kept.push(pos);
                        }
                    }
                    _ => kept.push(c),
                }
            }
            if kept.is_empty() && metering.is_empty() {
                None
            } else {
                core.add_cells(&kept, true);
                core.add_rows(&metering, true);
                let held = core.acc.len() + core.acc_meter.len();
                if held > ACC_ALARM_CELLS && !core.alarmed {
                    tracing::error!(cells = held, "money: the unsent spend accumulator has grown past its high-water mark; the store has not taken its work");
                    core.alarmed = true;
                } else if held <= ACC_ALARM_CELLS {
                    core.alarmed = false;
                }
                core.window_seq += 1;
                Some(Rec::Fold {
                    window_seq: core.window_seq,
                    cells: kept,
                    metering,
                })
            }
        };
        if !unposted.is_empty() {
            self.ledger.unposted(&unposted);
        }
        if rec.is_some() {
            self.stats.folds.fetch_add(1, Ordering::Relaxed);
            self.restamp();
            self.wake_sender.notify_one();
        }
        (rec, dead_recs)
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

    /// The LOWEST unresolved carve, or a new one asked of the writer.
    async fn front(&self) -> Option<Entry> {
        if let Some(e) = self.lock().entries.front().cloned() {
            return Some(e);
        }
        if self.lock().acc.is_empty() && self.lock().acc_meter.is_empty() {
            return None;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        if !self.post_msg(WriterMsg::Carve(tx)) {
            return None;
        }
        let batch = rx.await.ok().flatten()?;
        self.stats.carves.fetch_add(1, Ordering::Relaxed);
        Some(Entry::new(batch))
    }

    /// Work the LOWEST unresolved carve once: send or replay its two ops (each tracked on its own;
    /// parts one at a time). Answers whether it resolved a carve.
    pub async fn send_front(&self) -> bool {
        let _one = self.sending.lock().await;
        let Some(mut entry) = self.front().await else {
            return false;
        };
        let now = now_ms();
        // A carve unresolved 24 h after it was sent is dead-lettered, even mid-outage: its op ids
        // may not be re-issued past their retention.
        if now.saturating_sub(entry.batch.t_sent) > RETENTION_MS {
            self.dead_rest(
                &mut entry,
                DeadState::LandedUnknown,
                "unresolved at the op-id retention",
            )
            .await;
            return self.finish(entry);
        }
        let (u, m) = tokio::join!(
            self.work_kind(&entry, Kind::Usage),
            self.work_kind(&entry, Kind::Metering)
        );
        let unknown_u = self.apply(&mut entry, Kind::Usage, u).await;
        let unknown_m = self.apply(&mut entry, Kind::Metering, m).await;
        let now = now_ms();
        let since = entry.last_answer_ms.replace(now).unwrap_or(now);
        if unknown_u || unknown_m {
            // The bound runs only while the heartbeat succeeds: an outage is retried without limit
            // and never dead-lettered.
            if self.stamps.heartbeat_ok(now) {
                entry.unknown_ms = entry.unknown_ms.saturating_add(now.saturating_sub(since));
                if entry.unknown_ms > MAX_UNKNOWN.as_millis() as u64 {
                    self.dead_rest(
                        &mut entry,
                        DeadState::LandedUnknown,
                        "applied-unknown while the store's heartbeat succeeded",
                    )
                    .await;
                }
            }
        }
        if entry.done() {
            return self.finish(entry);
        }
        self.put_back(entry);
        false
    }

    fn put_back(&self, entry: Entry) {
        let mut core = self.lock();
        if let Some(f) = core.entries.front_mut() {
            if f.batch.seq == entry.batch.seq {
                *f = entry;
            }
        }
    }

    fn finish(&self, entry: Entry) -> bool {
        {
            let mut core = self.lock();
            if core
                .entries
                .front()
                .is_some_and(|f| f.batch.seq == entry.batch.seq)
            {
                core.entries.pop_front();
            }
            for kind in [Kind::Usage, Kind::Metering] {
                core.failing.remove(&entry.op(kind));
            }
        }
        self.stamps.progressed(now_ms());
        self.restamp();
        true
    }

    /// Send `kind`'s whole op, or its undone parts one at a time.
    async fn work_kind(&self, entry: &Entry, kind: Kind) -> KindWork {
        let state = match kind {
            Kind::Usage => entry.usage.clone(),
            Kind::Metering => entry.metering.clone(),
        };
        match state {
            KindState::Done => KindWork::Unchanged,
            KindState::Pending => {
                let out = self
                    .post(entry, kind, entry.op(kind), 0, entry.len(kind))
                    .await;
                KindWork::Whole(out)
            }
            KindState::Parts(parts) => {
                let mut outs = Vec::new();
                for (part, done) in parts {
                    if done {
                        continue;
                    }
                    let out = self.post(entry, kind, part.op, part.lo, part.hi).await;
                    let stop = matches!(out, Outcome::Unknown | Outcome::NotApplied);
                    outs.push((part, out));
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
        let res = match kind {
            Kind::Usage => {
                let body = record::usage_body(entry.batch.cells.get(lo..hi).unwrap_or_default());
                if body.is_empty() {
                    Ok(())
                } else {
                    self.store.add_usage_batch(op, &body).await
                }
            }
            Kind::Metering => {
                let body = entry.batch.metering.get(lo..hi).unwrap_or_default();
                if body.is_empty() {
                    Ok(())
                } else {
                    self.store.add_metering_batch(op, body).await
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
            Err(StoreFailure::Failed(t) | StoreFailure::Fault(t)) => {
                tracing::debug!(op = %op, error = %t, "money: an op's answer proves nothing; it replays under the same op id");
                Outcome::Unknown
            }
        };
        let now = now_ms();
        match &out {
            Outcome::Applied => {
                self.stamps.progressed(now);
            }
            Outcome::Refused(_) => {
                // A bisect makes progress.
                self.stamps.progressed(now);
                self.stats.refusals.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Unknown => {
                self.stats.replays.fetch_add(1, Ordering::Relaxed);
                let first = {
                    let mut core = self.lock();
                    let fresh = !core.failing.contains_key(&op);
                    core.failing.entry(op).or_insert(now);
                    fresh
                };
                if first {
                    self.lazy(vec![Rec::Failing { op, t_first: now }]);
                }
            }
            Outcome::NotApplied => {
                self.stats.replays.fetch_add(1, Ordering::Relaxed);
            }
        }
        out
    }

    /// Apply `kind`'s answers to `entry` (that op alone). Answers whether it is still
    /// applied-unknown.
    async fn apply(&self, entry: &mut Entry, kind: Kind, work: KindWork) -> bool {
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
        let mut ready = Vec::new();
        for (part, out) in outs {
            let Some(at) = parts.iter().position(|(p, _)| p.op == part.op) else {
                continue;
            };
            match out {
                Outcome::Applied => {
                    ready.push(Rec::Ready { op: part.op });
                    if kind == Kind::Usage {
                        self.ledger
                            .landed(entry.batch.cells.get(part.lo..part.hi).unwrap_or_default());
                    }
                    parts[at].1 = true;
                }
                Outcome::Refused(why) if part.hi - part.lo <= 1 => {
                    self.dead_range(entry, kind, (part.lo, part.hi), DeadState::Refused, &why)
                        .await;
                    parts[at].1 = true;
                }
                Outcome::Refused(_) => {
                    // BISECT the refused op: two halves, each under a new op, its sequence kept.
                    let mid = part.lo + (part.hi - part.lo) / 2;
                    let half = |lo, hi| {
                        (
                            Part {
                                op: Op::mint(),
                                lo,
                                hi,
                            },
                            false,
                        )
                    };
                    parts.splice(at..=at, [half(part.lo, mid), half(mid, part.hi)]);
                    split = true;
                }
                Outcome::NotApplied => {}
                Outcome::Unknown => unknown = true,
            }
        }
        if !ready.is_empty() {
            self.lazy(ready);
        }
        if split {
            let rec = Rec::Split {
                seq: entry.batch.seq,
                kind,
                parts: parts.iter().map(|(p, _)| *p).collect(),
            };
            if self.sync(vec![rec], Vec::new()).await.is_err() && self.spooled {
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
    async fn dead_rest(&self, entry: &mut Entry, state: DeadState, why: &str) {
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
                self.dead_range(entry, kind, r, state, why).await;
            }
            *entry.kind(kind) = KindState::Done;
        }
    }

    /// DEAD-LETTER cells (or rows) `lo..hi` of `entry`'s `kind` body: counts to the dead-letter file
    /// and a `dead` spool record in one synced round, and an alarm. A `refused` letter's cells leave
    /// `posted_hi`; a `landed-unknown` letter's stay.
    async fn dead_range(
        &self,
        entry: &Entry,
        kind: Kind,
        (lo, hi): (usize, usize),
        state: DeadState,
        why: &str,
    ) {
        let (cells, metering): (Vec<CellCount>, Vec<MeteringDelta>) = match kind {
            Kind::Usage => (
                entry.batch.cells.get(lo..hi).unwrap_or_default().to_vec(),
                Vec::new(),
            ),
            Kind::Metering => (
                Vec::new(),
                entry
                    .batch
                    .metering
                    .get(lo..hi)
                    .unwrap_or_default()
                    .to_vec(),
            ),
        };
        let (letter, moved) = {
            let mut core = self.lock();
            let id = core.next_dead;
            core.next_dead += 1;
            // A refused cell's CURRENT accumulator entry moves into the letter with it, so nothing
            // of that cell is carved after it (the `dead` record replays the same move).
            let mut cells = cells;
            let mut moved = Vec::new();
            if state == DeadState::Refused {
                for c in &mut cells {
                    if let Some(more) = core.acc.remove(&(c.bucket.clone(), c.window)) {
                        c.merge(&more);
                        moved.push(more);
                    }
                }
            }
            let letter = DeadLetter {
                id,
                kind,
                state,
                reason: why.to_string(),
                cells,
                absorbed: Vec::new(),
                metering,
                at_ms: now_ms(),
            };
            core.dead.push(letter.clone());
            (letter, moved)
        };
        let _ = moved;
        tracing::error!(seq = entry.batch.seq, kind = ?kind, state = ?state, reason = %why,
            buckets = ?letter.cells.iter().map(|c| c.bucket.as_str()).collect::<Vec<_>>(),
            "money: counts were dead-lettered; they await an operator's verdict");
        match state {
            DeadState::Refused => self.ledger.unposted(&letter.cells),
            DeadState::LandedUnknown => self.ledger.landed(&letter.cells),
        }
        self.stamps.progressed(now_ms());
        let recs = vec![Rec::Dead {
            seq: entry.batch.seq,
            kind,
            lo,
            hi,
        }];
        if let Err(e) = self.sync(recs, vec![DeadRec::Letter(letter)]).await {
            tracing::error!(error = %e, "money: a dead letter could not be synced");
        }
    }

    /// THE OPERATOR'S VERDICT on dead letter `id` (audited by the caller), written before any
    /// re-post: `NotLanded` re-posts its counts under a NEW op id; on EITHER verdict the negatives
    /// a `landed-unknown` letter absorbed are posted after.
    ///
    /// # Errors
    ///
    /// No such letter, `Landed` on a `refused` letter, or a re-post did not land.
    pub async fn clear(&self, id: u64, verdict: Verdict) -> Result<DeadLetter, String> {
        let letter = self
            .lock()
            .dead
            .iter()
            .find(|d| d.id == id)
            .cloned()
            .ok_or_else(|| format!("no dead letter {id}"))?;
        if verdict == Verdict::Landed && letter.state == DeadState::Refused {
            return Err("a refused dead letter never landed: re-post it".to_string());
        }
        self.sync(
            Vec::new(),
            vec![DeadRec::Verdict {
                id,
                landed: verdict == Verdict::Landed,
            }],
        )
        .await?;
        let landed = |r: Result<(), StoreFailure>| match r {
            Ok(()) | Err(StoreFailure::Conflict) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        if verdict == Verdict::NotLanded {
            let (u, m) = (Op::mint(), Op::mint());
            if !letter.cells.is_empty() {
                let body = record::usage_body(&letter.cells);
                landed(self.store.add_usage_batch(u, &body).await)?;
            }
            if !letter.metering.is_empty() {
                landed(self.store.add_metering_batch(m, &letter.metering).await)?;
            }
            if letter.state == DeadState::Refused {
                self.ledger.reposted(&letter.cells);
            }
        }
        if !letter.absorbed.is_empty() {
            let body = record::usage_body(&letter.absorbed);
            landed(self.store.add_usage_batch(Op::mint(), &body).await)?;
            self.ledger.landed(&letter.absorbed);
        }
        self.sync(Vec::new(), vec![DeadRec::Cleared { id }]).await?;
        self.lock().dead.retain(|d| d.id != id);
        Ok(letter)
    }

    /// DELIVER what is unrecorded (with a last take first at shutdown), until nothing is left or
    /// `deadline` passes; each refusal met extends it by [`REPLAY_PER_REFUSAL`]. Answers whether
    /// everything was delivered.
    pub async fn drain(&self, take_pending: bool, deadline: Duration) -> bool {
        let mut until = tokio::time::Instant::now() + deadline;
        let mut refusals = self.stats.refusals.load(Ordering::Relaxed);
        if take_pending {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if self.post_msg(WriterMsg::Take(Ack::Async(tx))) {
                let _ = rx.await;
            }
        }
        loop {
            if !self.working() {
                return true;
            }
            let met = self.stats.refusals.load(Ordering::Relaxed);
            if met > refusals {
                let more = u32::try_from(met - refusals).unwrap_or(u32::MAX);
                until += REPLAY_PER_REFUSAL * more;
                refusals = met;
            }
            if tokio::time::Instant::now() >= until {
                tracing::error!(
                    unresolved = self.unresolved(),
                    "money: spend was still unrecorded in the store at the deadline"
                );
                return false;
            }
            if !self.send_front().await {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(REPLAY_PAUSE.min(left)).await;
            }
        }
    }

    /// THE HEARTBEAT: every second while work is unresolved or strict mode is on.
    async fn heartbeat_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(HEARTBEAT_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            if self.working() || self.stamps.strict.load(Ordering::Relaxed) {
                self.beat().await;
            }
        }
    }

    /// One heartbeat write.
    pub async fn beat(&self) {
        if self.store.heartbeat().await.is_ok() {
            let now = now_ms();
            self.stamps.heartbeat_ok_ms.store(now, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
enum Outcome {
    Applied,
    Refused(String),
    NotApplied,
    Unknown,
}

#[derive(Debug)]
enum KindWork {
    Unchanged,
    Whole(Outcome),
    Parts(Vec<(Part, Outcome)>),
}

// ── the spool writer thread ──────────────────────────────────────────────────────────────────────

/// THE ONE SPOOL WRITER: an OS thread of its own, the only writer of the spool and the dead-letter
/// file. Every flush window it takes and writes the `fold` with every queued record in ONE `fsync`.
struct Writer {
    rec: std::sync::Weak<Recorder>,
    rx: mpsc::Receiver<WriterMsg>,
    spool: Option<Spool>,
    dead_file: Option<Ledgerette>,
    window: Duration,
}

impl Writer {
    fn run(mut self) {
        let mut next_take = Instant::now() + self.window;
        let mut alarmed = false;
        let mut lazy: Vec<Rec> = Vec::new();
        loop {
            let wait = next_take.saturating_duration_since(Instant::now());
            let first = match self.rx.recv_timeout(wait) {
                Ok(m) => Some(m),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            let mut msgs: Vec<WriterMsg> = first.into_iter().collect();
            while let Ok(m) = self.rx.try_recv() {
                msgs.push(m);
            }
            let Some(rec) = self.rec.upgrade() else {
                return;
            };
            let mut stop = false;
            let mut take_now = Instant::now() >= next_take;
            let (mut recs, mut dead, mut acks) = (Vec::new(), Vec::new(), Vec::new());
            let mut carves: Vec<tokio::sync::oneshot::Sender<Option<Batch>>> = Vec::new();
            for m in msgs {
                match m {
                    WriterMsg::Write {
                        recs: r,
                        dead: d,
                        ack,
                    } => {
                        recs.extend(r);
                        dead.extend(d);
                        acks.push(ack);
                    }
                    WriterMsg::Lazy(r) => lazy.extend(r),
                    WriterMsg::Carve(tx) => carves.push(tx),
                    WriterMsg::Take(ack) => {
                        take_now = true;
                        acks.push(ack);
                    }
                    WriterMsg::Stop(ack) => {
                        stop = true;
                        take_now = true;
                        acks.push(ack);
                    }
                }
            }
            if take_now {
                // FOLDS HAVE PRIORITY: the window's fold is first in the round, and the lazy
                // records (READY, `failing`) ride its `fsync`.
                let (fold, dead_recs) = rec.take();
                let mut first: Vec<Rec> = fold.into_iter().collect();
                first.append(&mut lazy);
                first.append(&mut recs);
                recs = first;
                dead.extend(dead_recs);
                next_take = Instant::now() + self.window;
            }
            // Carves last, in this same round: each `carve` record is synced before its body goes.
            let mut carved = Vec::new();
            for tx in carves {
                let batch = {
                    let mut core = rec.lock();
                    let b = core.carve();
                    if let Some(b) = &b {
                        core.entries.push_back(Entry::new(b.clone()));
                    }
                    b
                };
                if let Some(b) = &batch {
                    recs.push(Rec::Carve(b.clone()));
                }
                carved.push((tx, batch));
            }
            if !carved.is_empty() {
                rec.restamp();
            }
            let result = self.write(&rec, &recs, &dead);
            if let Err(e) = &result {
                tracing::error!(error = %e, "money spool: a round could not be made durable on the data directory; its work stays in RAM and is still sent");
            }
            for ack in acks {
                ack.send(result.clone());
            }
            for (tx, batch) in carved {
                let _ = tx.send(batch);
            }
            if let Some(s) = self.spool.as_mut() {
                let bytes = s.bytes();
                if bytes > ALARM_BYTES && !alarmed {
                    tracing::error!(bytes, "money spool: the spend spool has grown past its alarm size; the store has not taken its work");
                    alarmed = true;
                } else if bytes <= ALARM_BYTES {
                    alarmed = false;
                }
                let live = {
                    let core = rec.lock();
                    core.entries.is_empty().then(|| Rec::Fold {
                        window_seq: core.window_seq,
                        cells: core.acc.values().cloned().collect(),
                        metering: core.acc_meter.values().cloned().collect(),
                    })
                };
                if let Some(live) = live.filter(|_| bytes > COMPACT_BYTES) {
                    // Compaction rewrites the folds as one `fold`, and the dead-letter file from the
                    // letters standing.
                    match s.compact(&[live]) {
                        Ok(()) => {
                            if let Some(f) = &self.dead_file {
                                let bodies: Vec<Vec<u8>> = rec
                                    .dead_letters()
                                    .into_iter()
                                    .map(|l| serde_json::to_vec(&DeadRec::Letter(l)).unwrap_or_default())
                                    .collect();
                                if let Err(e) = f.rewrite(&bodies) {
                                    tracing::warn!(error = %e, "money spool: the dead-letter file could not be rewritten");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "money spool: compaction failed; the old generation stands");
                        }
                    }
                }
            }
            if stop {
                return;
            }
        }
    }

    fn write(&mut self, rec: &Recorder, recs: &[Rec], dead: &[DeadRec]) -> Result<(), String> {
        if let Some(f) = &self.dead_file {
            if !dead.is_empty() {
                let bodies: Vec<Vec<u8>> = dead
                    .iter()
                    .map(|d| serde_json::to_vec(d).unwrap_or_default())
                    .collect();
                f.append(&bodies).map_err(io_err)?;
            }
        }
        let Some(spool) = self.spool.as_mut() else {
            return Ok(());
        };
        if recs.is_empty() {
            return Ok(());
        }
        if spool.failed() {
            spool.reopen().map_err(io_err)?;
        }
        spool.append(recs).map_err(io_err)?;
        rec.stats.fsyncs.fetch_add(1, Ordering::Relaxed);
        *rec.stats
            .fsync_thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::thread::current().id());
        Ok(())
    }
}

/// Fold the spool's records into the core: the accumulator is the sum of the folds less what the
/// carves consumed and the drops removed; the carves not yet resolved are the queue.
fn fold(core: &mut Core, recs: Vec<Rec>) {
    let mut ready: BTreeSet<Op> = BTreeSet::new();
    let mut entries: BTreeMap<u64, Entry> = BTreeMap::new();
    let mut dead: Vec<(u64, Kind, usize, usize)> = Vec::new();
    for r in recs {
        match r {
            Rec::Fold {
                window_seq,
                cells,
                metering,
            } => {
                core.window_seq = core.window_seq.max(window_seq);
                core.add_cells(&cells, true);
                core.add_rows(&metering, true);
            }
            Rec::Carve(b) => {
                core.next_seq = core.next_seq.max(b.seq + 1);
                core.add_cells(&b.cells, false);
                core.add_rows(&b.metering, false);
                entries.insert(b.seq, Entry::new(b));
            }
            Rec::Ready { op } => {
                ready.insert(op);
            }
            Rec::Failing { op, t_first } => {
                core.failing.entry(op).or_insert(t_first);
            }
            Rec::Split { seq, kind, parts } => {
                if let Some(e) = entries.get_mut(&seq) {
                    *e.kind(kind) =
                        KindState::Parts(parts.into_iter().map(|p| (p, false)).collect());
                }
            }
            Rec::Dead { seq, kind, lo, hi } => {
                // The same move the live path made: the cells' accumulator entries went with them.
                if kind == Kind::Usage {
                    if let Some(e) = entries.get(&seq) {
                        for c in e.batch.cells.get(lo..hi).unwrap_or_default() {
                            core.acc.remove(&(c.bucket.clone(), c.window));
                        }
                    }
                }
                dead.push((seq, kind, lo, hi));
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
    core.entries = entries.into_values().filter(|e| !e.done()).collect();
}

#[cfg(test)]
#[path = "tests/recorder_tests.rs"]
mod tests;
