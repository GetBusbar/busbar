// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request,
};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_wal::{
    JournalRecord, QuarantineNote, Record, RecordClass, ShipError, Shipper, MEMORY_BUFFER_RECORDS,
};

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
    mut initial_fence: Option<Predicate>,
) -> Result<(), String> {
    loop {
        // Consume an already-read exact fence only once. A conflict always re-reads the
        // current lease; renewal never turns this into a stale-predicate retry loop.
        let current = match initial_fence.take() {
            Some(predicate) => Some(predicate),
            None => lease.predicate(calls)?,
        };
        let Some(predicate) = current else {
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
    if super::usage_recovery::is_recovery_record(record) {
        return put_immutable_record(calls, lease, record);
    }
    let mut audit = match super::audit_heads::prepare(calls, record)? {
        super::audit_heads::Write::Ordinary => None,

        super::audit_heads::Write::Recorded => return Ok(()),
        super::audit_heads::Write::New(advance) => Some(advance),
    };
    let parts = parts_of(record)?;
    let first_fence = lease.predicate(calls)?;
    let fenced = first_fence.is_some();
    if let Some(first_fence) = first_fence {
        fenced_mutation(
            calls,
            lease,
            Mutation::DeleteRange {
                schema: JOURNAL_SCHEMA.into(),
                prefix: part_key(record.node, record.node_seq, 0)[..16].to_vec(),
                exact_key_length: 18,
            },
            Some(first_fence),
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
                None,
            )?;
        } else {
            wait_for(calls.record_put(JOURNAL_SCHEMA, &key, value)).map_err(|f| f.to_string())?;
        }
    }
    Ok(())
}

/// Recovery records have immutable addresses and bytes. Unlike an arbitrary mutation, a retry
/// with a fresh transaction identity is safe even after conditional receipt retention expires:
/// absent predicates prevent any existing part from being replaced.
fn put_immutable_record(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    record: &Record,
) -> Result<(), String> {
    let (request, fences, parts) = immutable_request(calls, lease, record)?;
    // One call only: an unknown journal transition is not an unknown usage outcome. The next
    // lane attempt uses a new conditional id and the same immutable record under a current fence.
    let decision = wait_for(calls.record_transaction(&request));
    confirm_immutable_record(calls, lease, &fences, record, &parts)
        .map_err(|why| format!("recovery journal record is not confirmed ({decision:?}): {why}"))
}

fn immutable_request(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    record: &Record,
) -> Result<(Request, Vec<Predicate>, Vec<RecordBytes>), String> {
    if !calls.supports_record_transaction() {
        return Err("usage recovery requires atomic conditional record transactions".into());
    }
    let fences = lease.recovery_predicates(calls, record.node)?;
    let parts = parts_of(record)?;
    let mut predicates = fences.clone();
    let mut mutations = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let index = u16::try_from(index).map_err(|_| "too many recovery parts")?;
        let key = part_key(record.node, record.node_seq, index).to_vec();
        predicates.push(Predicate {
            schema: JOURNAL_SCHEMA.into(),
            key: key.clone(),
            expected: Expected::Absent,
        });
        mutations.push(Mutation::Put {
            schema: JOURNAL_SCHEMA.into(),
            key,
            value: part.as_slice().to_vec(),
        });
    }
    let request = super::conditional::candidate(predicates, mutations);
    // This validates the actual extension frame, including part keys and both predicate and
    // mutation envelopes, against the existing 16 MiB ABI bound before the Store sees it.
    drop(request.encode_held().map_err(|why| {
        format!("recovery transaction cannot be encoded within the ABI byte bound: {why}")
    })?);
    Ok((request, fences, parts))
}

fn confirm_immutable_record(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    fences: &[Predicate],
    record: &Record,
    parts: &[RecordBytes],
) -> Result<(), String> {
    if !lease.recovery_fence_matches(calls, record.node, fences)? {
        return Err("the node fence changed before recovery readback".into());
    }
    confirm_record_parts(calls, record, parts)?;
    if !lease.recovery_fence_matches(calls, record.node, fences)? {
        return Err("the node fence changed during recovery readback".into());
    }
    Ok(())
}

pub(super) fn confirm_record_bytes(calls: &dyn StoreCalls, record: &Record) -> Result<(), String> {
    confirm_record_parts(calls, record, &parts_of(record)?)
}

fn confirm_record_parts(
    calls: &dyn StoreCalls,
    record: &Record,
    parts: &[RecordBytes],
) -> Result<(), String> {
    let prefix = part_key(record.node, record.node_seq, 0);
    let actual = wait_for(calls.record_scan(JOURNAL_SCHEMA, &prefix[..16], SCAN_LIMIT))
        .map_err(|why| format!("recovery record readback failed: {why}"))?;
    if actual.len() != parts.len() {
        return Err("recovery record part count differs".into());
    }
    for (index, ((key, actual), expected)) in actual.iter().zip(parts).enumerate() {
        let index = u16::try_from(index).map_err(|_| "too many recovery parts")?;
        if key.as_slice() != part_key(record.node, record.node_seq, index)
            || actual.as_slice() != expected.as_slice()
        {
            return Err("an exact recovery record part is absent or differs".into());
        }
    }
    Ok(())
}

pub fn read_chain(calls: &dyn StoreCalls, node: u64) -> Result<Vec<Record>, String> {
    let (records, torn) = scan_chain(calls, node)?;
    warn_torn(node, torn.last().copied());
    Ok(records)
}

/// Fold bounded Store pages in key order. Neither a node's journal nor its historical bodies
/// accumulate here: at most one record's bounded parts are assembled beside one 256-row page.
fn fold_stored_records(
    calls: &dyn StoreCalls,
    node: u64,
    prefix: Vec<u8>,
    mut visit: impl FnMut(Record) -> Result<(), String>,
) -> Result<(), String> {
    struct Partial {
        sequence: u64,
        count: usize,
        next: usize,
        valid: bool,
        bytes: Vec<u8>,
    }
    fn finish(
        node: u64,
        pending: &mut Option<Partial>,
        visit: &mut impl FnMut(Record) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(record) = pending.take() {
            if record.valid && record.next == record.count {
                visit(Record::new(node, record.sequence, record.bytes))?;
            }
        }
        Ok(())
    }
    const PAGE: u32 = 256;
    let mut prefixes = vec![prefix];
    let mut previous_key: Option<Vec<u8>> = None;
    let mut pending: Option<Partial> = None;
    while let Some(prefix) = prefixes.pop() {
        let page = wait_for(calls.record_scan(JOURNAL_SCHEMA, &prefix, PAGE))
            .map_err(|why| format!("the Store journal page is unreadable: {why}"))?;
        if page.len() > PAGE as usize
            || page
                .iter()
                .any(|(key, _)| key.len() != 18 || !key.starts_with(&prefix))
            || page.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err("invalid Store journal page".into());
        }
        // With one selector byte left, 256 distinct exact-length keys exhaust the namespace.
        if page.len() == PAGE as usize && prefix.len() < 17 {
            for byte in (0..=u8::MAX).rev() {
                let mut child = prefix.clone();
                child.push(byte);
                prefixes.push(child);
            }
            continue;
        }
        for (key, value) in page {
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err("Store journal pages repeat or reorder a part".into());
            }
            previous_key = Some(key.clone());
            let sequence = u64::from_be_bytes(
                key[8..16]
                    .try_into()
                    .map_err(|_| "invalid journal sequence")?,
            );
            let part = usize::from(u16::from_be_bytes(
                key[16..18].try_into().map_err(|_| "invalid journal part")?,
            ));
            let raw = value.as_slice();
            let count = raw
                .get(..2)
                .and_then(|count| count.try_into().ok())
                .map(u16::from_be_bytes)
                .map(usize::from)
                .filter(|count| *count > 0)
                .ok_or_else(|| "invalid journal part count".to_string())?;
            if pending
                .as_ref()
                .is_some_and(|record| record.sequence != sequence)
            {
                finish(node, &mut pending, &mut visit)?;
            }
            let record = pending.get_or_insert_with(|| Partial {
                sequence,
                count,
                next: 0,
                valid: part == 0,
                bytes: Vec::new(),
            });
            if record.next >= record.count {
                return Err("unexpected trailing journal part".into());
            }
            if record.count != count || record.next != part {
                record.valid = false;
                record.bytes.clear();
            }
            if record.valid {
                record.bytes.extend_from_slice(&raw[2..]);
            }
            record.next = part + 1;
        }
    }
    finish(node, &mut pending, &mut visit)
}

fn checked_record(record: Record) -> Result<JournalRecord, String> {
    let decoded = JournalRecord::decode(&record.body).map_err(|why| why.to_string())?;
    if decoded.identity() != record.identity() || decoded.encode() != record.body {
        return Err("recovery journal key and sealed record identity differ".into());
    }
    busbar_kernel_wal::verify_journal(std::slice::from_ref(&decoded))
        .map_err(|why| why.to_string())?;
    Ok(decoded)
}

pub(super) fn read_record_exact(
    calls: &dyn StoreCalls,
    node: u64,
    sequence: u64,
) -> Result<JournalRecord, String> {
    let key = part_key(node, sequence, 0);
    let mut found = None;
    fold_stored_records(calls, node, key[..16].to_vec(), |record| {
        if record.identity() != (node, sequence) || found.is_some() {
            return Err("exact journal lookup returned another record".into());
        }
        found = Some(checked_record(record)?);
        Ok(())
    })?;
    found.ok_or_else(|| "selected recovery journal record is missing or incomplete".into())
}

#[derive(Clone, Copy)]
struct ChainPoint {
    node: u64,
    sequence: u64,
    hash: [u8; 32],
    previous: [u8; 32],
}

fn bridge_covers(
    calls: &dyn StoreCalls,
    previous: ChainPoint,
    current: ChainPoint,
) -> Result<bool, String> {
    let mut covered = false;
    fold_stored_records(
        calls,
        current.node,
        current.node.to_be_bytes().to_vec(),
        |record| {
            let record = checked_record(record)?;
            let bridge = (record.class == RecordClass::ChainBreak)
                .then(|| QuarantineNote::read(&record.body).and_then(|note| note.bridge))
                .flatten();
            drop(record);
            let Some(bridge) = bridge else {
                return Ok(());
            };
            if bridge.before.0 != current.node || current.sequence <= bridge.before.1 {
                return Ok(());
            }
            let named_after = bridge.after == Some((current.node, current.sequence));
            if named_after && bridge.before == (previous.node, previous.sequence) {
                covered = true;
                return Ok(());
            }
            if (named_after || bridge.after.is_none()) && bridge.before.1 <= previous.sequence {
                let anchor = read_record_exact(calls, bridge.before.0, bridge.before.1)?;
                covered |= anchor.hash == current.previous;
            }
            Ok(())
        },
    )?;
    Ok(covered)
}

/// An exact record used by one read operation, bound to the final fresh node verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecordSeal {
    pub node: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}
impl RecordSeal {
    pub(super) fn of(record: &JournalRecord) -> Self {
        Self {
            node: record.node,
            sequence: record.node_seq,
            hash: record.hash,
        }
    }
}

/// The same sealed hash/sequence authority as the ordinary journal reader, folded without a
/// history Vec. Quarantine bridge lookup rescans only on an actual gap, retaining no bridge log.
pub(super) fn verify_stored_chain(calls: &dyn StoreCalls, node: u64) -> Result<(), String> {
    verify_stored_chain_with_seals(calls, node, &[])
}

/// Verify the entire node exactly as before, and bind every requested, sorted record seal to
/// that fresh fold. The caller bounds the transcript; no historical payloads are retained.
pub(super) fn verify_stored_chain_with_seals(
    calls: &dyn StoreCalls,
    node: u64,
    seals: &[RecordSeal],
) -> Result<(), String> {
    if seals.iter().any(|seal| seal.node != node)
        || seals
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
    {
        return Err("invalid same-read journal seal transcript".into());
    }
    let mut matched = 0;
    let mut previous: Option<ChainPoint> = None;
    fold_stored_records(calls, node, node.to_be_bytes().to_vec(), |record| {
        let record = checked_record(record)?;
        let current = ChainPoint {
            node: record.node,
            sequence: record.node_seq,
            hash: record.hash,
            previous: record.prev_hash,
        };
        drop(record);
        if let Some(previous) = previous {
            let follows = current.previous == previous.hash
                && current.sequence == previous.sequence.saturating_add(1);
            if !follows && !bridge_covers(calls, previous, current)? {
                return Err("the streamed Store journal has a broken hash link or sequence".into());
            }
        }
        if let Some(seal) = seals.get(matched) {
            if seal.sequence < current.sequence {
                return Err("a same-read recovery record is missing from its verified node".into());
            }
            if seal.sequence == current.sequence {
                if seal.hash != current.hash {
                    return Err(
                        "a same-read recovery record changed before node verification".into(),
                    );
                }
                matched += 1;
            }
        }
        previous = Some(current);
        Ok(())
    })?;
    if matched != seals.len() {
        return Err("a same-read recovery record is missing from its verified node".into());
    }
    Ok(())
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

    pub(crate) fn bind_recovery_identity(&self, host: &str, node: u64) -> Result<(), String> {
        self.lane
            .lease
            .bind_recovery_identity(self.lane.calls.as_ref(), host, node)
    }

    pub(super) fn recovery_predicates(&self, node: u64) -> Result<Vec<Predicate>, String> {
        if self.lane.lock().stopped {
            return Err("the recovery journal writer has retired".into());
        }
        self.lane
            .lease
            .recovery_predicates(self.lane.calls.as_ref(), node)
    }

    pub(super) fn recovery_fence_matches(
        &self,
        node: u64,
        before: &[Predicate],
    ) -> Result<bool, String> {
        if self.lane.lock().stopped {
            return Err("the recovery journal writer has retired".into());
        }
        self.lane
            .lease
            .recovery_fence_matches(self.lane.calls.as_ref(), node, before)
    }

    pub(super) fn confirm_recovery_record(&self, record: &Record) -> Result<(), String> {
        let predicates = self.recovery_predicates(record.node)?;
        confirm_immutable_record(
            self.lane.calls.as_ref(),
            &self.lane.lease,
            &predicates,
            record,
            &parts_of(record)?,
        )
    }

    pub(super) fn validate_recovery_frame(&self, node: u64, body_len: usize) -> Result<(), String> {
        let length = busbar_kernel_wal::JOURNAL_HEADER_BYTES
            .checked_add(body_len)
            .filter(|length| {
                *length as u64 <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES
            })
            .ok_or_else(|| "recovery candidate exceeds the ABI byte bound".to_string())?;
        // Sequence and digest bytes have fixed width: this exact-length stand-in measures the
        // complete frame before allocating any journal sequence or retaining a candidate.
        let measure = Record::new(node, 0, vec![0; length]);
        immutable_request(self.lane.calls.as_ref(), &self.lane.lease, &measure).map(|_| ())
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
mod recovery_record_tests {
    use super::*;
    use crate::root::store_double::RecordSlots;

    fn identity(slots: &RecordSlots, host: &str) -> (u64, HeldLease) {
        let taken = super::super::take_node(slots.calls().as_ref(), host).unwrap();
        let lease = HeldLease::default();
        lease.hold(taken.lease.unwrap());
        lease
            .bind_recovery_identity(slots.calls().as_ref(), host, taken.id)
            .unwrap();
        (taken.id, lease)
    }

    #[test]
    fn first_delete_fence_is_exact_and_a_conflict_rechecks_current_custody() {
        use super::super::store_identity::{lease_row, set_lease_expiry};
        use std::sync::atomic::AtomicUsize;

        for release in [false, true] {
            let slots = RecordSlots::new();
            let host = format!("first-delete-fence-{release}");
            let (node, lease) = identity(&slots, &host);
            let first = lease.predicate(slots.calls().as_ref()).unwrap().unwrap();
            let expected = first.expected.clone();
            let probes = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&probes);
            let probe_slots = slots.clone();
            slots.on_transaction(move |request| {
                if !request.mutations.iter().any(|mutation| {
                    matches!(mutation, Mutation::DeleteRange { schema, .. } if schema == JOURNAL_SCHEMA)
                }) {
                    return None;
                }
                if observed.fetch_add(1, Ordering::AcqRel) == 0 {
                    assert_eq!(request.predicates[0].expected, expected);
                    let calls = probe_slots.calls();
                    let (_, expires) = lease_row(calls.as_ref(), &host).unwrap();
                    set_lease_expiry(calls.as_ref(), &host, if release { 0 } else { expires + 1 });
                } else {
                    assert_ne!(request.predicates[0].expected, expected,
                        "a conflicted first CAS must use the freshly read raw fence");
                }
                None
            });
            let record = Record::new(node, 17, vec![42; PART_BYTES + 1]);
            let result = put_record(slots.calls().as_ref(), &lease, &record);
            slots.on_transaction(|_| None);
            if release {
                assert!(
                    result.is_err(),
                    "released custody cannot delete or put any part"
                );
                assert_eq!(probes.load(Ordering::Acquire), 1);
                assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);
            } else {
                result.expect("normal renewal refreshes the exact conditional predicate");
                assert_eq!(probes.load(Ordering::Acquire), 2);
                confirm_record_bytes(slots.calls().as_ref(), &record).unwrap();
            }
        }
    }

    #[test]
    fn lost_transaction_ack_confirms_only_the_exact_whole_immutable_record() {
        let slots = RecordSlots::new();
        let (node, lease) = identity(&slots, "recovery-exact");
        let record = Record::new(node, 7, vec![42; PART_BYTES * 2 + 1]);
        slots.lose_transaction_acks(true);
        put_immutable_record(slots.calls().as_ref(), &lease, &record).unwrap();
        let puts = slots.puts();
        put_immutable_record(slots.calls().as_ref(), &lease, &record).unwrap();
        assert_eq!(slots.puts(), puts, "immutable replay never replaces parts");
        slots.corrupt(JOURNAL_SCHEMA, &part_key(node, 7, 1));
        assert!(put_immutable_record(slots.calls().as_ref(), &lease, &record).is_err());
        assert_eq!(
            slots.puts(),
            puts,
            "a conflict must not repair divergent bytes"
        );
    }

    #[test]
    fn partial_record_cannot_confirm_and_is_never_overwritten() {
        let slots = RecordSlots::new();
        let (node, lease) = identity(&slots, "recovery-partial");
        let record = Record::new(node, 8, vec![9; PART_BYTES + 1]);
        let parts = parts_of(&record).unwrap();
        slots.put_row(JOURNAL_SCHEMA, &part_key(node, 8, 0), parts[0].as_slice());
        let puts = slots.puts();
        assert!(put_immutable_record(slots.calls().as_ref(), &lease, &record).is_err());
        assert_eq!(slots.puts(), puts);
    }

    #[test]
    fn unreadable_record_or_changed_fence_cannot_confirm_unknown_transition() {
        let slots = RecordSlots::new();
        let (node, lease) = identity(&slots, "recovery-fence");
        let record = Record::new(node, 9, vec![3; 40]);
        slots.lose_transaction_acks(true);
        put_immutable_record(slots.calls().as_ref(), &lease, &record).unwrap();
        slots.fail_reads(true);
        assert!(put_immutable_record(slots.calls().as_ref(), &lease, &record).is_err());
        slots.fail_reads(false);
        super::super::store_identity::set_lease_expiry(slots.calls().as_ref(), "recovery-fence", 0);
        assert!(put_immutable_record(slots.calls().as_ref(), &lease, &record).is_err());
    }

    #[test]
    fn unknown_not_applied_returns_without_replaying_the_conditional_id() {
        use std::sync::atomic::AtomicUsize;
        let slots = RecordSlots::new();
        let (node, lease) = identity(&slots, "recovery-unknown");
        let seen = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&seen);
        slots.on_transaction(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            Some(busbar_contract::store_calls::StoreFailure::Failed(
                "unknown".into(),
            ))
        });
        let record = Record::new(node, 10, vec![8; 40]);
        assert!(put_immutable_record(slots.calls().as_ref(), &lease, &record).is_err());
        assert_eq!(seen.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn complete_transaction_frame_bound_is_checked_before_the_store_call() {
        let slots = RecordSlots::new();
        let (node, lease) = identity(&slots, "recovery-frame");
        let record = Record::new(
            node,
            11,
            vec![0; busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize],
        );
        let before = slots.puts();
        assert!(
            put_immutable_record(slots.calls().as_ref(), &lease, &record)
                .unwrap_err()
                .contains("ABI byte bound")
        );
        assert_eq!(slots.puts(), before);
    }

    #[test]
    fn streamed_journal_pages_preserve_actual_seals_and_exact_record_addresses() {
        use std::sync::atomic::AtomicUsize;
        let slots = RecordSlots::new();
        let taken =
            super::super::take_node(slots.calls().as_ref(), "stream-journal-pages").unwrap();
        let lane = JournalLane::start(slots.calls(), "stream-journal-test").unwrap();
        lane.hold_lease(taken.lease.unwrap());
        lane.bind_recovery_identity("stream-journal-pages", taken.id)
            .unwrap();
        let mut book = super::super::build_on_store(
            &super::super::DurabilityConfig { data_dir: None },
            taken.id,
            lane.clone(),
            None,
        )
        .unwrap();
        let entries: Vec<_> = (0u64..300)
            .map(|index| {
                busbar_kernel_wal::Entry::new(
                    RecordClass::Transaction,
                    index.to_be_bytes().to_vec(),
                )
            })
            .collect();
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        let sealed = book
            .journal
            .append(&token, busbar_contract::caps::StepName::Meter, &entries)
            .unwrap()
            .sealed;
        lane.wait_acked(taken.id, sealed.last().unwrap().node_seq, ACK_DEADLINE)
            .unwrap();
        let scans = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&scans);
        slots.on_scan(move || {
            observed.fetch_add(1, Ordering::Relaxed);
        });
        verify_stored_chain(slots.calls().as_ref(), taken.id).unwrap();
        assert!(
            scans.load(Ordering::Relaxed) > 1,
            "more than one bounded page must be consumed"
        );
        let expected = &sealed[149];
        assert_eq!(
            read_record_exact(slots.calls().as_ref(), taken.id, expected.node_seq).unwrap(),
            *expected
        );
        slots.corrupt(JOURNAL_SCHEMA, &part_key(taken.id, expected.node_seq, 0));
        assert!(verify_stored_chain(slots.calls().as_ref(), taken.id).is_err());
    }

    #[test]
    fn streamed_journal_crosses_only_the_existing_quarantine_bridge_authority() {
        let slots = RecordSlots::new();
        let taken =
            super::super::take_node(slots.calls().as_ref(), "stream-journal-bridge").unwrap();
        let lane = JournalLane::start(slots.calls(), "stream-bridge-test").unwrap();
        lane.hold_lease(taken.lease.unwrap());
        lane.bind_recovery_identity("stream-journal-bridge", taken.id)
            .unwrap();
        let mut book = super::super::build_on_store(
            &super::super::DurabilityConfig { data_dir: None },
            taken.id,
            lane.clone(),
            None,
        )
        .unwrap();
        let start = book.journal.next_seq();
        let note = busbar_kernel_wal::Quarantine {
            segment: 0,
            segment_file: None,
            offset: 0,
            damage_at: 0,
            bytes: 1,
            why: None,
            identities: vec![(taken.id, start + 1)],
            unverified: Vec::new(),
            damaged: Vec::new(),
            at_unix_ms: 0,
            kept: busbar_kernel_wal::QuarantineKept::Memory,
            before: Some((taken.id, start)),
            after: Some((taken.id, start + 2)),
        };
        let entries = [
            busbar_kernel_wal::Entry::new(RecordClass::Transaction, b"before".to_vec()),
            busbar_kernel_wal::Entry::new(RecordClass::Transaction, b"quarantined".to_vec()),
            busbar_kernel_wal::Entry::new(RecordClass::Transaction, b"after".to_vec()),
            busbar_kernel_wal::Entry::new(RecordClass::ChainBreak, note.body()),
        ];
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        let sealed = book
            .journal
            .append(&token, busbar_contract::caps::StepName::Meter, &entries)
            .unwrap()
            .sealed;
        lane.wait_acked(taken.id, sealed.last().unwrap().node_seq, ACK_DEADLINE)
            .unwrap();
        let remove = |sequence| {
            let key = part_key(taken.id, sequence, 0);
            let request = super::super::conditional::candidate(
                lane.recovery_predicates(taken.id).unwrap(),
                vec![Mutation::DeleteRange {
                    schema: JOURNAL_SCHEMA.into(),
                    prefix: key[..16].to_vec(),
                    exact_key_length: 18,
                }],
            );
            wait_for(slots.calls().record_transaction(&request)).unwrap();
        };
        remove(start + 1);
        let decoded =
            busbar_kernel_wal::decode_run(&read_chain(slots.calls().as_ref(), taken.id).unwrap())
                .unwrap();
        busbar_kernel_wal::verify_journal(&decoded).unwrap();
        verify_stored_chain(slots.calls().as_ref(), taken.id).unwrap();
        remove(start + 3);
        assert!(verify_stored_chain(slots.calls().as_ref(), taken.id).is_err());
    }
}

#[cfg(test)]
#[path = "../tests/store_chain.rs"]
mod tests;
