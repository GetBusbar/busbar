// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::sdk::store::conditional::{Decision, Mutation};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_wal::{Record, ShipError, Shipper, MEMORY_BUFFER_RECORDS};

use super::store_identity::{HeldLease, NodeLease};

pub const JOURNAL_SCHEMA: &str = "busbar.journal.v1";

pub const RECORD_SLOTS: &str = "record_put, record_get and record_scan";

pub const PART_BYTES: usize = busbar_contract::MAX_RECORD_BYTES - 2;

pub const ACK_DEADLINE: Duration = Duration::from_secs(5);

const SCAN_LIMIT: u32 = 1 << 16;

const RETRY_FIRST: Duration = Duration::from_millis(50);
const RETRY_MOST: Duration = Duration::from_secs(1);

#[must_use]
pub fn part_key(node: u64, node_seq: u64, part: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..8].copy_from_slice(&node.to_be_bytes());
    key[8..16].copy_from_slice(&node_seq.to_be_bytes());
    key[16..].copy_from_slice(&part.to_be_bytes());
    key
}

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

pub(crate) fn wait_for<F: Future>(fut: F) -> F::Output {
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

fn fenced_mutation(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    mutation: Mutation,
) -> Result<(), String> {
    loop {
        let Some(predicate) = lease.predicate(calls)? else {
            return Err("a journal fence was released while its writer was active".into());
        };
        let request = super::conditional::candidate(vec![predicate], vec![mutation.clone()]);
        match super::conditional::decide(calls, &request)? {
            Decision::Applied => return Ok(()),
            Decision::ConditionConflict => continue,
        }
    }
}

pub(super) fn put_record(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    record: &Record,
) -> Result<(), String> {
    let mut audit = match super::audit_heads::prepare(calls, record)? {
        super::audit_heads::Write::Ordinary => None,

        super::audit_heads::Write::Recorded => return Ok(()),
        super::audit_heads::Write::New(advance) => Some(advance),
    };
    let parts = parts_of(record)?;
    let fenced = lease.predicate(calls)?.is_some();
    if fenced {
        fenced_mutation(
            calls,
            lease,
            Mutation::DeleteRange {
                schema: JOURNAL_SCHEMA.into(),
                prefix: part_key(record.node, record.node_seq, 0)[..16].to_vec(),
                exact_key_length: 18,
            },
        )?;
    }
    for (part, value) in parts.iter().enumerate() {
        let part = u16::try_from(part).map_err(|_| "too many parts".to_string())?;
        let key = part_key(record.node, record.node_seq, part);
        if usize::from(part) + 1 == parts.len() {
            if let Some(advance) = audit.take() {
                advance.commit(calls, lease, key.to_vec(), value.as_slice().to_vec())?;
                continue;
            }
        }
        if fenced {
            fenced_mutation(
                calls,
                lease,
                Mutation::Put {
                    schema: JOURNAL_SCHEMA.into(),
                    key: key.to_vec(),
                    value: value.as_slice().to_vec(),
                },
            )?;
        } else {
            wait_for(calls.record_put(JOURNAL_SCHEMA, &key, value)).map_err(|f| f.to_string())?;
        }
    }
    Ok(())
}

pub fn read_chain(calls: &dyn StoreCalls, node: u64) -> Result<Vec<Record>, String> {
    let (records, torn) = scan_chain(calls, node)?;
    warn_torn(node, torn.last().copied());
    Ok(records)
}

fn warn_torn(node: u64, seq: Option<u64>) {
    if let Some(seq) = seq {
        tracing::warn!(
            node,
            node_seq = seq,
            "the stored journal holds a record whose parts are not all there; it is left off"
        );
    }
}

pub(super) fn read_chain_beside(lane: &JournalLane, node: u64) -> Result<Vec<Record>, String> {
    let calls = lane.calls();
    let (records, mut torn) = scan_chain(calls.as_ref(), node)?;
    if !torn.is_empty() {
        let held: std::collections::HashSet<u64> = lane
            .queued()
            .into_iter()
            .filter(|record| record.node == node)
            .map(|record| record.node_seq)
            .collect();
        torn.retain(|seq| !held.contains(seq));
    }
    if !torn.is_empty() {
        let (_, again) = scan_chain(calls.as_ref(), node)?;
        torn.retain(|seq| again.contains(seq));
    }
    warn_torn(node, torn.last().copied());
    Ok(records)
}

fn scan_chain(calls: &dyn StoreCalls, node: u64) -> Result<(Vec<Record>, Vec<u64>), String> {
    let mut records = Vec::new();
    let mut torn: Vec<u64> = Vec::new();
    for block in 0u64.. {
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
                    if part != 0 && torn.last() != Some(&seq) {
                        torn.push(seq);
                    }
                }
            }
        }
        finish(&mut at, node, &mut records, &mut torn);
    }
    Ok((records, torn))
}

pub(super) fn whole_chain(
    journal: &busbar_kernel_wal::Journal,
    lane: &JournalLane,
) -> std::io::Result<Result<Vec<busbar_kernel_wal::JournalRecord>, busbar_kernel_wal::JournalBreak>>
{
    HeldChain::of(journal, lane)?.read()
}

pub(super) struct HeldChain {
    lane: JournalLane,
    node: u64,

    through: u64,

    held: Vec<Record>,
}

impl HeldChain {
    pub(super) fn of(
        journal: &busbar_kernel_wal::Journal,
        lane: &JournalLane,
    ) -> std::io::Result<Self> {
        let mut held = lane.queued();
        held.extend(journal.log().owed().iter().cloned());
        held.extend(journal.log().read_back()?.records);
        Ok(HeldChain {
            lane: lane.clone(),
            node: journal.node(),
            through: journal.next_seq(),
            held,
        })
    }

    pub(super) fn store(&self) -> &str {
        self.lane.store()
    }

    pub(super) fn read(
        self,
    ) -> std::io::Result<
        Result<Vec<busbar_kernel_wal::JournalRecord>, busbar_kernel_wal::JournalBreak>,
    > {
        let HeldChain {
            lane,
            node,
            through,
            held,
        } = self;
        let (stored, torn) = off_runtime(|| scan_chain(lane.calls().as_ref(), node))
            .map_err(std::io::Error::other)?;
        let mut chain: std::collections::BTreeMap<u64, Record> = std::collections::BTreeMap::new();
        for record in stored
            .into_iter()
            .chain(held)
            .filter(|record| record.node == node && record.node_seq < through)
        {
            chain.entry(record.node_seq).or_insert(record);
        }
        warn_torn(
            node,
            torn.into_iter()
                .rev()
                .find(|seq| *seq < through && !chain.contains_key(seq)),
        );
        let records: Vec<Record> = chain.into_values().collect();
        Ok(busbar_kernel_wal::decode_run(&records)
            .and_then(|decoded| busbar_kernel_wal::verify_journal(&decoded).map(|()| decoded)))
    }
}

fn finish(
    at: &mut Option<(u64, u16, Vec<u8>, u16)>,
    node: u64,
    records: &mut Vec<Record>,
    torn: &mut Vec<u64>,
) {
    if let Some((seq, got, bytes, count)) = at.take() {
        if got == count {
            records.push(Record::new(node, seq, bytes));
        } else if torn.last() != Some(&seq) {
            torn.push(seq);
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

struct Lane {
    calls: Arc<dyn StoreCalls>,
    store: String,
    capacity: usize,
    state: Mutex<LaneState>,

    work: Condvar,

    moved: Condvar,

    full: AtomicBool,

    lease: HeldLease,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Lane {
    fn lock(&self) -> MutexGuard<'_, LaneState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_full(&self, state: &LaneState) {
        self.full.store(
            state.stopped
                || self.lease.lost()
                || state.turned_away
                || state.queue.len() >= self.capacity,
            Ordering::Release,
        );
    }

    fn run(self: Arc<Self>) {
        let mut pause = RETRY_FIRST;
        loop {
            let next = {
                let mut state = self.lock();
                while state.queue.is_empty() && !state.stopped {
                    state = self.work.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                match state.queue.front() {
                    Some(_) if state.stopped && state.refusal.is_some() => return,
                    Some(front) => front.clone(),
                    None => return,
                }
            };
            match put_record(self.calls.as_ref(), &self.lease, &next) {
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
                    self.set_full(&state);
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
    pub fn start(calls: Arc<dyn StoreCalls>, store: &str) -> Result<Self, String> {
        Self::with_capacity(calls, store, MEMORY_BUFFER_RECORDS)
    }

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
            lease: HeldLease::default(),
            worker: Mutex::new(None),
        });
        let worker = Arc::clone(&lane);
        let handle = std::thread::Builder::new()
            .name("busbar-journal-lane".to_string())
            .spawn(move || worker.run())
            .map_err(|e| format!("the journal's store lane could not start: {e}"))?;
        *lane.worker.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        Ok(JournalLane {
            _owner: Arc::new(Owner(Arc::clone(&lane))),
            lane,
        })
    }

    #[must_use]
    pub fn store(&self) -> &str {
        &self.lane.store
    }

    #[must_use]
    pub fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::clone(&self.lane.calls)
    }

    pub(super) fn initialize_heads(
        &self,
        node: u64,
        records: &[busbar_kernel_wal::JournalRecord],
    ) -> Result<busbar_kernel_audit::HeadHistory, String> {
        super::audit_heads::initialize_fenced(
            self.lane.calls.as_ref(),
            node,
            records,
            &self.lane.lease,
        )
    }

    pub fn hold_lease(&self, lease: NodeLease) {
        self.lane.lease.hold(lease);
    }

    pub fn refresh_held_lease(&self) {
        self.lane.lease.refresh(self.lane.calls.as_ref());
        self.lane.set_full(&self.lane.lock());
    }

    pub fn release_held_lease(&self) {
        {
            let mut state = self.lane.lock();
            if !state.queue.is_empty() || state.turned_away {
                tracing::warn!(
                    "the journal still owns queued records; its host lease was not released"
                );
                return;
            }
            state.stopped = true;
            self.lane.set_full(&state);
        }
        self.lane.work.notify_all();
        let worker = self
            .lane
            .worker
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(worker) = worker {
            if worker.join().is_err() {
                tracing::error!(
                    "the journal writer did not retire cleanly; its host lease was not released"
                );
                return;
            }
        }
        self.lane.lease.release(self.lane.calls.as_ref());
    }

    #[must_use]
    pub fn shipper(&self) -> Box<dyn Shipper<Record>> {
        Box::new(LaneShipper(self.clone()))
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.lane.lock().queue.len()
    }

    fn queued(&self) -> Vec<Record> {
        self.lane.lock().queue.iter().cloned().collect()
    }

    #[must_use]
    pub fn refuses_money(&self) -> Option<String> {
        if !self.lane.full.load(Ordering::Acquire) && !self.lane.lease.lost() {
            return None;
        }
        let state = self.lane.lock();
        if self.lane.lease.lost() || state.stopped {
            return Some("this node's journal identity is retired or held by another process; new billable work is refused".into());
        }
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

pub(crate) fn off_runtime<T>(wait: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    }
}

struct LaneShipper(JournalLane);

impl Shipper<Record> for LaneShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        if records.is_empty() {
            return Ok(());
        }
        let lane = &self.0.lane;
        let mut state = lane.lock();
        if state.stopped || lane.lease.lost() {
            return Err(ShipError::Unavailable(
                "the journal writer no longer owns an active node identity".into(),
            ));
        }

        if !state.queue.is_empty()
            && state.queue.len().saturating_add(records.len()) > lane.capacity
        {
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
