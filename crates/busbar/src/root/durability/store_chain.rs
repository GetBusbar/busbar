// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JOURNAL ON THE CONFIGURED STORE: where a node with no data directory keeps its chain, and how
//! it gets the chain back at boot (ARCHITECT 2026-10-07 H3 ruling (a)-(c); BUSBAR-1.6.0.md THE DESIGN
//! §7: the journal carries the record body, "the in-memory ring of 1024 is only a cache, and an older
//! `/audit/range` decodes from the journal").
//!
//! ## The write
//!
//! Each journal record goes to the configured store through its store v3 `record_put` slot, under
//! [`JOURNAL_SCHEMA`], keyed `node ‖ node_seq ‖ part`, each big-endian, so `record_scan` returns the
//! chain in chain order. No new store slot: an individual idempotent `record_put` is the write (the
//! store ABI is locked, ARCHITECT H2-U10-OPID). A slot carries at most
//! [`busbar_contract::MAX_RECORD_BYTES`] per record and a journal record is a 160-byte header plus its
//! body, so a record crosses as one or more PARTS, each `part count (u16 BE) ‖ chunk`. A re-put of a
//! part is an upsert of the same bytes, so a retry is harmless.
//!
//! ## The lane: write-behind, bounded, never dropping
//!
//! The journal appends under the book's one lock on the request path, so the store is never called
//! there (THE DESIGN §11.2: no blocking on the hot path). The journal's shipper hands each committed
//! batch to [`JournalLane`] — a bounded queue the HOST owns, drained by one worker thread of its own
//! (§11.11 R4: one host-owned bounded lane), which puts the records in chain order and waits on each
//! store answer off every runtime worker. A record leaves the queue only once the store took every
//! part of it.
//!
//! A store that REFUSES a put leaves the record at the head of the queue; the worker offers it again
//! after a growing pause and nothing behind it overtakes it. While the queue has room the units keep
//! being served: their records wait there. When it is FULL the lane turns the journal's next batch
//! away, the journal retains that batch and re-offers it on its next append (the log's own retained
//! batch), and the node FAILS CLOSED — a new money-bearing unit is refused 503 with the reason
//! ([`JournalLane::refuses_money`]) until the store takes what is queued. No record is dropped.
//!
//! ## The read
//!
//! [`read_chain`] scans the schema under this node's key, one block of 256 sequence numbers at a
//! time, and reassembles each record from its parts. A record whose parts are not all there is the
//! newest one a crash cut short and is left off: it was never acknowledged, so nothing was ever told
//! it was kept.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_wal::{Record, ShipError, Shipper, MEMORY_BUFFER_RECORDS};

/// The record schema the journal's records are kept under in the configured store.
pub const JOURNAL_SCHEMA: &str = "busbar.journal.v1";

/// The store slots a journal kept in the store needs, as a boot refusal names them.
pub const RECORD_SLOTS: &str = "record_put, record_get and record_scan";

/// The most bytes of a record one part carries: the slot's per-record bound less the part count.
pub const PART_BYTES: usize = busbar_contract::MAX_RECORD_BYTES - 2;

/// How long a durable admin verb waits for the store to acknowledge its record before it refuses.
pub const ACK_DEADLINE: Duration = Duration::from_secs(5);

/// The most entries one block scan may answer: 256 sequence numbers, each in parts. A block that
/// answers this many is refused rather than read short.
const SCAN_LIMIT: u32 = 1 << 16;

/// The first pause before a refused put is offered again, and the longest.
const RETRY_FIRST: Duration = Duration::from_millis(50);
const RETRY_MOST: Duration = Duration::from_secs(1);

/// The store key of `part` of the record `(node, node_seq)`: every field big-endian, so the store's
/// key order is chain order.
#[must_use]
pub fn part_key(node: u64, node_seq: u64, part: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..8].copy_from_slice(&node.to_be_bytes());
    key[8..16].copy_from_slice(&node_seq.to_be_bytes());
    key[16..].copy_from_slice(&part.to_be_bytes());
    key
}

/// The parts `record` crosses as, in order: each `part count ‖ chunk`.
///
/// # Errors
///
/// A record so large its parts cannot be counted in a `u16`.
fn parts_of(record: &Record) -> Result<Vec<RecordBytes>, String> {
    let chunks: Vec<&[u8]> = if record.body.is_empty() {
        vec![&[][..]]
    } else {
        record.body.chunks(PART_BYTES).collect()
    };
    let count = u16::try_from(chunks.len()).map_err(|_| {
        format!(
            "journal record ({}, {}) is too large to put",
            record.node, record.node_seq
        )
    })?;
    chunks
        .into_iter()
        .map(|chunk| {
            let mut value = Vec::with_capacity(2 + chunk.len());
            value.extend_from_slice(&count.to_be_bytes());
            value.extend_from_slice(chunk);
            RecordBytes::new(value).map_err(|n| format!("a {n}-byte part is over the slot's bound"))
        })
        .collect()
}

/// Wait for `fut` on this thread: the store's calls are futures the dispatcher completes on its own
/// workers, and the two callers here (the boot's read and the lane's worker) are threads that may
/// wait. Never called on a runtime worker's request path.
pub(super) fn wait_for<F: Future>(fut: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::thread::park();
    }
}

/// Put every part of `record`, in order.
fn put_record(calls: &dyn StoreCalls, record: &Record) -> Result<(), String> {
    for (part, value) in parts_of(record)?.iter().enumerate() {
        let part = u16::try_from(part).map_err(|_| "too many parts".to_string())?;
        let key = part_key(record.node, record.node_seq, part);
        wait_for(calls.record_put(JOURNAL_SCHEMA, &key, value)).map_err(|f| f.to_string())?;
    }
    Ok(())
}

/// THE CHAIN THE STORE KEPT for `node`, oldest first, each record reassembled from its parts.
///
/// # Errors
///
/// The store refused or failed a scan, or a block answered more entries than one scan may carry.
pub fn read_chain(calls: &dyn StoreCalls, node: u64) -> Result<Vec<Record>, String> {
    let mut records = Vec::new();
    let mut torn: Option<u64> = None;
    for block in 0u64.. {
        // `node ‖ the first seven bytes of the sequence number`: 256 numbers a block.
        let mut prefix = [0u8; 15];
        prefix[..8].copy_from_slice(&node.to_be_bytes());
        prefix[8..].copy_from_slice(&block.to_be_bytes()[1..]);
        let entries = wait_for(calls.record_scan(JOURNAL_SCHEMA, &prefix, SCAN_LIMIT))
            .map_err(|f| format!("the store would not read the journal back: {f}"))?;
        if entries.is_empty() {
            break;
        }
        if entries.len() >= SCAN_LIMIT as usize {
            return Err(format!(
                "a block of the stored journal answers {} entries, more than one scan carries",
                entries.len()
            ));
        }
        let mut at: Option<(u64, u16, Vec<u8>, u16)> = None;
        for (key, value) in entries {
            let (Some(seq), Some(part), Some(count)) = (
                key.get(8..16)
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_be_bytes),
                key.get(16..18)
                    .and_then(|b| b.try_into().ok())
                    .map(u16::from_be_bytes),
                value
                    .as_slice()
                    .get(..2)
                    .and_then(|b| b.try_into().ok())
                    .map(u16::from_be_bytes),
            ) else {
                continue;
            };
            let chunk = &value.as_slice()[2..];
            match &mut at {
                Some((s, next, bytes, c)) if *s == seq && *next == part && *c == count => {
                    bytes.extend_from_slice(chunk);
                    *next += 1;
                }
                _ => {
                    finish(&mut at, node, &mut records, &mut torn);
                    at = (part == 0).then(|| (seq, 1, chunk.to_vec(), count));
                    if part != 0 {
                        torn = Some(seq);
                    }
                }
            }
        }
        finish(&mut at, node, &mut records, &mut torn);
    }
    if let Some(seq) = torn {
        // Left off, never spliced in: a record missing a part was never acknowledged whole. Only the
        // newest can be in this state on a store that kept what it acknowledged; one further back
        // shows as the chain break the boot's verify reports.
        tracing::warn!(
            node,
            node_seq = seq,
            "the stored journal holds a record whose parts are not all there; it is left off"
        );
    }
    Ok(records)
}

/// Close the record being reassembled: whole, it joins `records`; short, it is noted as torn.
fn finish(
    at: &mut Option<(u64, u16, Vec<u8>, u16)>,
    node: u64,
    records: &mut Vec<Record>,
    torn: &mut Option<u64>,
) {
    if let Some((seq, got, bytes, count)) = at.take() {
        if got == count {
            records.push(Record::new(node, seq, bytes));
        } else {
            *torn = Some(seq);
        }
    }
}

/// What the lane holds, under one lock.
#[derive(Default)]
struct LaneState {
    /// The records the store has not taken yet, in chain order.
    queue: VecDeque<Record>,
    /// Per node, the highest sequence number the store took.
    acked: HashMap<u64, u64>,
    /// The store's last refusal, until a put succeeds.
    refusal: Option<String>,
    /// How many refusals there have been, so a waiter can tell one after its record joined.
    refusals: u64,
    /// The journal's last batch was turned away for room and is retained by the journal.
    turned_away: bool,
    /// Every handle is gone: the worker stops once nothing is left it can put.
    stopped: bool,
}

/// The lane itself, shared by its handles and its worker.
struct Lane {
    calls: Arc<dyn StoreCalls>,
    store: String,
    capacity: usize,
    state: Mutex<LaneState>,
    /// The worker waits here for records, and for the pause after a refusal.
    work: Condvar,
    /// A waiter waits here for an acknowledgement or a refusal.
    moved: Condvar,
    /// The fail-closed fact, readable without the lock on the request path.
    full: AtomicBool,
}

impl Lane {
    fn lock(&self) -> MutexGuard<'_, LaneState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_full(&self, state: &LaneState) {
        self.full.store(
            state.turned_away || state.queue.len() >= self.capacity,
            Ordering::Release,
        );
    }

    /// The worker: put the head of the queue until the store takes it, then the next.
    fn run(self: Arc<Self>) {
        let mut pause = RETRY_FIRST;
        loop {
            let next = {
                let mut state = self.lock();
                while state.queue.is_empty() && !state.stopped {
                    state = self.work.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                match state.queue.front() {
                    // Stopped with a store that is refusing: nobody is left to be told.
                    Some(_) if state.stopped && state.refusal.is_some() => return,
                    Some(front) => front.clone(),
                    None => return,
                }
            };
            match put_record(self.calls.as_ref(), &next) {
                Ok(()) => {
                    pause = RETRY_FIRST;
                    let mut state = self.lock();
                    if state.queue.front().map(Record::identity) == Some(next.identity()) {
                        state.queue.pop_front();
                    }
                    let mark = state.acked.entry(next.node).or_insert(0);
                    *mark = (*mark).max(next.node_seq);
                    state.refusal = None;
                    self.set_full(&state);
                    self.moved.notify_all();
                }
                Err(why) => {
                    let mut state = self.lock();
                    tracing::warn!(
                        store = %self.store,
                        node = next.node,
                        node_seq = next.node_seq,
                        reason = %why,
                        "the store did not take a journal record; it is retained and offered again"
                    );
                    state.refusal = Some(why);
                    state.refusals = state.refusals.saturating_add(1);
                    self.moved.notify_all();
                    if !state.stopped {
                        let _ = self
                            .work
                            .wait_timeout(state, pause)
                            .unwrap_or_else(|p| p.into_inner());
                    }
                    pause = (pause * 2).min(RETRY_MOST);
                }
            }
        }
    }
}

/// Stops the worker once the last handle is gone.
struct Owner(Arc<Lane>);

impl Drop for Owner {
    fn drop(&mut self) {
        self.0.lock().stopped = true;
        self.0.work.notify_all();
    }
}

/// THE HOST'S BOUNDED LANE TO THE STORE for the journal's records. Cheap to clone; every clone is the
/// same lane.
#[derive(Clone)]
pub struct JournalLane {
    lane: Arc<Lane>,
    _owner: Arc<Owner>,
}

impl std::fmt::Debug for JournalLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalLane")
            .field("kept_in", &self.lane.store)
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

impl JournalLane {
    /// Open the lane to the store named `store`, reached through `calls`, bounded at
    /// [`MEMORY_BUFFER_RECORDS`] records, and start its worker.
    ///
    /// # Errors
    ///
    /// The worker thread could not be started.
    pub fn start(calls: Arc<dyn StoreCalls>, store: &str) -> Result<Self, String> {
        Self::with_capacity(calls, store, MEMORY_BUFFER_RECORDS)
    }

    /// [`JournalLane::start`], bounded at `capacity` records.
    ///
    /// # Errors
    ///
    /// As [`JournalLane::start`].
    pub fn with_capacity(
        calls: Arc<dyn StoreCalls>,
        store: &str,
        capacity: usize,
    ) -> Result<Self, String> {
        let lane = Arc::new(Lane {
            calls,
            store: store.to_string(),
            capacity: capacity.max(1),
            state: Mutex::new(LaneState::default()),
            work: Condvar::new(),
            moved: Condvar::new(),
            full: AtomicBool::new(false),
        });
        let worker = Arc::clone(&lane);
        std::thread::Builder::new()
            .name("busbar-journal-lane".to_string())
            .spawn(move || worker.run())
            .map_err(|e| format!("the journal's store lane could not start: {e}"))?;
        Ok(JournalLane {
            _owner: Arc::new(Owner(Arc::clone(&lane))),
            lane,
        })
    }

    /// The configured store's name.
    #[must_use]
    pub fn store(&self) -> &str {
        &self.lane.store
    }

    /// The store's calls, for the boot's read-back.
    #[must_use]
    pub fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::clone(&self.lane.calls)
    }

    /// The journal's shipper over this lane.
    #[must_use]
    pub fn shipper(&self) -> Box<dyn Shipper<Record>> {
        Box::new(LaneShipper(self.clone()))
    }

    /// How many records wait for the store.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.lane.lock().queue.len()
    }

    /// WHY A NEW MONEY-BEARING UNIT IS REFUSED, or `None` while the lane has room. One atomic read
    /// when it has room; the reason is built only for a refusal.
    #[must_use]
    pub fn refuses_money(&self) -> Option<String> {
        if !self.lane.full.load(Ordering::Acquire) {
            return None;
        }
        let state = self.lane.lock();
        Some(format!(
            "this node's journal is full: {} records await the store `{}`, which has not taken \
             them ({}); new billable work is refused until it does",
            state.queue.len(),
            self.lane.store,
            state
                .refusal
                .as_deref()
                .unwrap_or("it has not answered yet")
        ))
    }

    /// `Err` with the reason while the store's last answer was a refusal, or the lane is full: a
    /// durable verb then refuses before it records anything.
    ///
    /// # Errors
    ///
    /// The reason the store is not taking the journal's records.
    pub fn healthy(&self) -> Result<(), String> {
        if let Some(why) = self.refuses_money() {
            return Err(why);
        }
        match &self.lane.lock().refusal {
            Some(why) => Err(format!(
                "the store `{}` is refusing the journal's records: {why}",
                self.lane.store
            )),
            None => Ok(()),
        }
    }

    /// WAIT UNTIL THE STORE TOOK `(node, node_seq)` — and so every record before it — or refused on
    /// the way, or `deadline` passed. Off a runtime worker where one is waiting.
    ///
    /// # Errors
    ///
    /// The store refused, or did not answer in time; the record stays queued and is offered again.
    pub fn wait_acked(&self, node: u64, node_seq: u64, deadline: Duration) -> Result<(), String> {
        off_runtime(|| {
            let until = Instant::now() + deadline;
            let mut state = self.lane.lock();
            let seen = state.refusals;
            loop {
                if state.acked.get(&node).is_some_and(|&mark| mark >= node_seq) {
                    return Ok(());
                }
                if state.refusals > seen {
                    return Err(format!(
                        "the store `{}` did not take the record: {}; it is retained on this \
                         node's journal and offered again",
                        self.lane.store,
                        state.refusal.as_deref().unwrap_or("refused")
                    ));
                }
                let now = Instant::now();
                if now >= until {
                    return Err(format!(
                        "the store `{}` did not acknowledge the record within {}s; it is retained \
                         on this node's journal and offered again",
                        self.lane.store,
                        deadline.as_secs()
                    ));
                }
                state = self
                    .lane
                    .moved
                    .wait_timeout(state, until - now)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
        })
    }

    /// Wait until nothing is queued, at most `deadline`. `true` when the store took everything.
    #[must_use]
    pub fn drain(&self, deadline: Duration) -> bool {
        off_runtime(|| {
            let until = Instant::now() + deadline;
            let mut state = self.lane.lock();
            loop {
                if state.queue.is_empty() {
                    return true;
                }
                let now = Instant::now();
                if now >= until {
                    return false;
                }
                state = self
                    .lane
                    .moved
                    .wait_timeout(state, until - now)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
        })
    }
}

/// Run a wait that blocks this thread: on a multi-threaded runtime's worker it first hands the
/// worker's other tasks on, so no task queued behind it waits on the store.
pub(super) fn off_runtime<T>(wait: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    }
}

/// The journal's shipper: hands each batch to the lane, whole or not at all. Never calls the store.
struct LaneShipper(JournalLane);

impl Shipper<Record> for LaneShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        if records.is_empty() {
            return Ok(());
        }
        let lane = &self.0.lane;
        let mut state = lane.lock();
        if state.queue.len().saturating_add(records.len()) > lane.capacity {
            state.turned_away = true;
            lane.set_full(&state);
            return Err(ShipError::Unavailable(format!(
                "the journal's lane to the store `{}` is full ({} records wait)",
                lane.store,
                state.queue.len()
            )));
        }
        state.queue.extend(records.iter().cloned());
        state.turned_away = false;
        lane.set_full(&state);
        drop(state);
        lane.work.notify_one();
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/store_chain.rs"]
mod tests;
