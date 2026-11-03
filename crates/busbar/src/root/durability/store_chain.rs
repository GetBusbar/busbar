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
    // Preflight before cleanup. Oversized conditional frames retain the original split path.
    let atomic_parts = audit.as_ref().and_then(|advance| {
        let mutations: Vec<_> = parts
            .iter()
            .enumerate()
            .map(|(part, value)| Mutation::Put {
                schema: JOURNAL_SCHEMA.into(),
                key: part_key(
                    record.node,
                    record.node_seq,
                    u16::try_from(part).expect("parts_of already bounded the part count"),
                )
                .to_vec(),
                value: value.as_slice().to_vec(),
            })
            .collect();
        advance
            .parts_fit(&mutations, first_fence.clone())
            .then_some(mutations)
    });
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
    if let Some(mutations) = atomic_parts {
        return audit
            .take()
            .expect("preflighted audit advance")
            .commit_parts(calls, lease, mutations);
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

const AUDIT_GROUP_RECORDS: usize = 16;

pub(super) struct AuditGroup {
    advance: super::audit_heads::GroupAdvance,
    records: Vec<Record>,
    parts: Vec<Mutation>,
    cleanup: Vec<Mutation>,
    planning_fence: Predicate,
    node_predicate: Predicate,
}

pub(super) fn prepare_audit_group(
    calls: &dyn StoreCalls,
    lease: &HeldLease,
    offered: &[Record],
) -> Result<Option<AuditGroup>, String> {
    if offered.len() < 2 {
        return Ok(None);
    }
    let Some(planning_fence) = lease.predicate(calls)? else {
        return Ok(None);
    };
    let Some(node_predicate) = lease.node_predicate(calls, offered[0].node)? else {
        return Ok(None);
    };
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut previous: Option<JournalRecord> = None;
    for record in offered.iter().take(AUDIT_GROUP_RECORDS) {
        bytes = match bytes.checked_add(record.body.len()) {
            Some(bytes)
                if bytes as u64 <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES =>
            {
                bytes
            }
            _ => break,
        };
        let Ok(decoded) = JournalRecord::decode(&record.body) else {
            break;
        };
        if decoded.class != RecordClass::Transaction
            || decoded.identity() != record.identity()
            || decoded.encode() != record.body
            || decoded.digest_of_body() != decoded.body_hash
            || decoded.digest_of_chain() != decoded.hash
            || previous.as_ref().is_some_and(|old| {
                old.node != decoded.node
                    || old.node_seq.checked_add(1) != Some(decoded.node_seq)
                    || old.hash != decoded.prev_hash
            })
            || busbar_kernel_audit::journal::head_from_journal_body(&decoded.body)?.is_none()
        {
            break;
        }
        previous = Some(decoded);
        count += 1;
    }
    if count < 2 {
        return Ok(None);
    }
    let Some(advance) = super::audit_heads::prepare_group(calls, &offered[..count])? else {
        return Ok(None);
    };
    let records = offered[..advance.len()].to_vec();
    let mut parts = Vec::new();
    let mut cleanup = Vec::new();
    for record in &records {
        cleanup.push(Mutation::DeleteRange {
            schema: JOURNAL_SCHEMA.into(),
            prefix: part_key(record.node, record.node_seq, 0)[..16].to_vec(),
            exact_key_length: 18,
        });
        for (index, value) in parts_of(record)?.into_iter().enumerate() {
            parts.push(Mutation::Put {
                schema: JOURNAL_SCHEMA.into(),
                key: part_key(
                    record.node,
                    record.node_seq,
                    u16::try_from(index).map_err(|_| "too many grouped parts")?,
                )
                .to_vec(),
                value: value.as_slice().to_vec(),
            });
        }
    }
    // Preflight uses the captured exact fence. Same-holder renewal preserves its fixed row size;
    // actual cleanup/publication still obtain fresh exact predicates.
    let fence = planning_fence.clone();
    let mut final_request = advance.request(&parts, fence.clone())?;
    final_request.predicates.push(node_predicate.clone());
    let cleanup_request = super::conditional::candidate(
        vec![advance.predecessor(), fence, node_predicate.clone()],
        cleanup.clone(),
    );
    if final_request.encode_held().is_err() || cleanup_request.encode_held().is_err() {
        if advance.recorded() {
            return Err("recorded audit group exceeds its bounded proof frame".into());
        }
        return Ok(None);
    }
    if advance.recorded()
        && (!advance.initial_matches(&advance.raw_head(calls)?)
            || !lease.fence_matches(calls, &planning_fence)?)
    {
        return Err("audit group checkpoint or custody changed during planning".into());
    }
    Ok(Some(AuditGroup {
        advance,
        records,
        parts,
        cleanup,
        planning_fence,
        node_predicate,
    }))
}

impl AuditGroup {
    pub(super) fn len(&self) -> usize {
        self.records.len()
    }
    fn node_matches(&self, calls: &dyn StoreCalls) -> Result<bool, String> {
        let raw = wait_for(calls.record_get(&self.node_predicate.schema, &self.node_predicate.key))
            .map_err(|why| why.to_string())?;
        Ok(raw
            .as_ref()
            .map(|raw| Expected::Bytes(raw.as_slice().to_vec()))
            == Some(self.node_predicate.expected.clone()))
    }
    fn confirmed(&self, calls: &dyn StoreCalls, lease: &HeldLease) -> Result<bool, String> {
        if !self.node_matches(calls)? {
            return Err("audit group node registry changed".into());
        }
        let before = lease
            .predicate(calls)?
            .ok_or("audit group no longer holds a lease")?;
        let final_raw = self.advance.final_raw()?;
        if self.advance.raw_head(calls)? != Some(final_raw.clone()) {
            return Ok(false);
        }
        for record in &self.records {
            confirm_record_bytes(calls, record)?;
        }
        if !self.advance.samples_match(calls, true)? {
            return Err("committed audit group is missing an immutable sample".into());
        }
        if self.advance.raw_head(calls)? != Some(final_raw)
            || !lease.fence_matches(calls, &before)?
            || !self.node_matches(calls)?
        {
            return Err("audit group ownership or checkpoint changed during readback".into());
        }
        Ok(true)
    }
    pub(super) fn commit(&self, calls: &dyn StoreCalls, lease: &HeldLease) -> Result<(), String> {
        // An exact committed group is proved before ANY destructive cleanup, including reoffer.
        if !lease.fence_matches(calls, &self.planning_fence)? {
            return Err("audit group planning custody changed".into());
        }
        let raw = self.advance.raw_head(calls)?;
        if raw == Some(self.advance.final_raw()?) {
            return if self.confirmed(calls, lease)? {
                Ok(())
            } else {
                Err("audit group committed checkpoint changed during readback".into())
            };
        }
        if self.advance.recorded() {
            return Err("recorded audit group no longer matches its checkpoint".into());
        }
        if !self.advance.initial_matches(&raw) {
            return Err("audit group checkpoint predecessor changed before cleanup".into());
        }
        loop {
            let fence = lease
                .predicate(calls)?
                .ok_or("audit group no longer holds a lease")?;
            let request = super::conditional::candidate(
                vec![
                    self.advance.predecessor(),
                    fence,
                    self.node_predicate.clone(),
                ],
                self.cleanup.clone(),
            );
            match super::conditional::decide(calls, &request)? {
                Decision::Applied => break,
                Decision::ConditionConflict => {
                    if !self.node_matches(calls)? {
                        return Err("audit group node registry changed during cleanup".into());
                    }
                    if !self.advance.initial_matches(&self.advance.raw_head(calls)?) {
                        if self.confirmed(calls, lease)? {
                            return Ok(());
                        }
                        return Err("audit group checkpoint changed during cleanup".into());
                    }
                }
            }
        }
        loop {
            let fence = lease
                .predicate(calls)?
                .ok_or("audit group no longer holds a lease")?;
            let mut request = self.advance.request(&self.parts, fence)?;
            request.predicates.push(self.node_predicate.clone());
            match super::conditional::decide(calls, &request)? {
                Decision::Applied => return Ok(()),
                Decision::ConditionConflict => {
                    if self.confirmed(calls, lease)? {
                        return Ok(());
                    }
                    if !self.advance.initial_matches(&self.advance.raw_head(calls)?)
                        || !self.advance.samples_match(calls, false)?
                    {
                        return Err("audit group checkpoint or immutable sample changed".into());
                    }
                    // A normal same-holder renewal retries ONLY final publication, not cleanup.
                }
            }
        }
    }
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

type JournalPage = Vec<(Vec<u8>, RecordBytes)>;
const JOURNAL_PAGE_ROWS: u32 = 256;
const JOURNAL_PREFETCH: usize = 16;
const JOURNAL_PROBE_ROWS: u32 = JOURNAL_PAGE_ROWS * JOURNAL_PREFETCH as u32;
enum JournalReadWork {
    Prefix(Vec<u8>),
    Page(JournalPage),
}

fn valid_journal_page(prefix: &[u8], page: &JournalPage, limit: u32) -> Result<(), String> {
    if page.len() > limit as usize
        || page
            .iter()
            .any(|(key, _)| key.len() != 18 || !key.starts_with(prefix))
        || page.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err("invalid Store journal page".into());
    }
    // Check fatal part-envelope errors even in a sibling whose read budget was refused.
    // No successful answer may be discarded/re-read into apparently valid data.
    if page.iter().any(|(_, value)| {
        value
            .as_slice()
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_be_bytes)
            .is_none_or(|count| count == 0)
    }) {
        return Err("invalid journal part count".into());
    }
    Ok(())
}

fn journal_page_window(
    calls: &dyn StoreCalls,
    prefixes: &[Vec<u8>],
) -> Vec<Result<JournalPage, busbar_contract::store_calls::StoreFailure>> {
    let mut pending: Vec<_> = prefixes
        .iter()
        .map(|prefix| calls.record_scan(JOURNAL_SCHEMA, prefix, JOURNAL_PAGE_ROWS))
        .collect();
    let mut answers: Vec<_> = (0..pending.len()).map(|_| None).collect();
    // Poll existing owned Store futures together; no tasks, threads, timers or borrowed ABI
    // buffers survive a call. Every future is complete before any answer is visited.
    wait_for(std::future::poll_fn(|cx| {
        for (index, future) in pending.iter_mut().enumerate() {
            if answers[index].is_none() {
                if let Poll::Ready(answer) = future.as_mut().poll(cx) {
                    answers[index] = Some(answer);
                }
            }
        }
        if answers.iter().all(Option::is_some) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }));
    answers
        .into_iter()
        .map(|answer| answer.expect("every page future completed"))
        .collect()
}

fn visit_journal_pages(
    calls: &dyn StoreCalls,
    prefix: Vec<u8>,
    mut visit: impl FnMut(JournalPage) -> Result<(), String>,
) -> Result<(), String> {
    use busbar_contract::store_calls::StoreFailure;
    // One complete answer avoids radix descent for ordinary journals while retaining the
    // same 4096-row ownership bound. A saturated answer is an arbitrary sorted subset;
    // discard it before starting the unchanged exhaustive traversal, never infer siblings.
    match wait_for(calls.record_scan(JOURNAL_SCHEMA, &prefix, JOURNAL_PROBE_ROWS)) {
        Ok(page) => {
            valid_journal_page(&prefix, &page, JOURNAL_PROBE_ROWS)?;
            if page.len() < JOURNAL_PROBE_ROWS as usize {
                return visit(page);
            }
        }
        Err(StoreFailure::Overloaded) => {}
        Err(why) => return Err(format!("the Store journal page is unreadable: {why}")),
    }
    let mut work = vec![JournalReadWork::Prefix(prefix)];
    let mut ready_pages = 0usize;
    let mut serial = false;
    while let Some(next) = work.pop() {
        match next {
            JournalReadWork::Page(page) => {
                ready_pages = ready_pages
                    .checked_sub(1)
                    .ok_or("invalid journal page budget")?;
                visit(page)?;
            }
            JournalReadWork::Prefix(prefix) => {
                let available = JOURNAL_PREFETCH
                    .checked_sub(ready_pages)
                    .filter(|n| *n > 0)
                    .ok_or("journal page budget exhausted before ordered consumption")?;
                let limit = if serial { 1 } else { available };
                let mut prefixes = vec![prefix];
                while prefixes.len() < limit {
                    if !matches!(work.last(), Some(JournalReadWork::Prefix(_))) {
                        break;
                    }
                    if let Some(JournalReadWork::Prefix(prefix)) = work.pop() {
                        prefixes.push(prefix);
                    }
                }
                let answers = journal_page_window(calls, &prefixes);
                let mut overloaded = false;
                // Inspect the ENTIRE untouched window before falling back. Failed/Fault,
                // named Refused, conflicting opids or malformed successful pages are fatal.
                for (prefix, answer) in prefixes.iter().zip(&answers) {
                    match answer {
                        Ok(page) => valid_journal_page(prefix, page, JOURNAL_PAGE_ROWS)?,
                        Err(StoreFailure::Overloaded) if !serial => overloaded = true,
                        Err(why) => {
                            return Err(format!("the Store journal page is unreadable: {why}"))
                        }
                    }
                }
                if overloaded {
                    serial = true;
                }
                // A depth-first stack preserves exactly the old lexicographic consumption.
                // At most sixteen pages/futures TOTAL belong to this traversal, independent of
                // prefix depth. Empty pages and saturated parent pages release slots now;
                // nonempty later siblings remain behind every child of an earlier parent.
                for (prefix, answer) in prefixes.into_iter().zip(answers).rev() {
                    match answer {
                        Err(StoreFailure::Overloaded) => work.push(JournalReadWork::Prefix(prefix)),
                        Err(_) => unreachable!("all fatal page answers were rejected"),
                        Ok(page) if page.is_empty() => {}
                        Ok(page)
                            if page.len() == JOURNAL_PAGE_ROWS as usize && prefix.len() < 17 =>
                        {
                            for byte in (0..=u8::MAX).rev() {
                                let mut child = prefix.clone();
                                child.push(byte);
                                work.push(JournalReadWork::Prefix(child));
                            }
                        }
                        Ok(page) => {
                            ready_pages += 1;
                            work.push(JournalReadWork::Page(page));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Fold bounded Store pages in key order. Neither a node's journal nor its historical bodies
/// accumulate here: one record is assembled beside at most sixteen 256-row pages/futures.
pub(super) fn fold_stored_records(
    calls: &dyn StoreCalls,
    node: u64,
    prefix: Vec<u8>,
    visit: impl FnMut(Record) -> Result<(), String>,
) -> Result<(), String> {
    fold_stored_records_observed(calls, node, prefix, &mut false, visit)
}

// Preserve ordinary torn-tail omission while keeping its provenance for retry eligibility.
fn fold_stored_records_observed(
    calls: &dyn StoreCalls,
    node: u64,
    prefix: Vec<u8>,
    omitted: &mut bool,
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
        omitted: &mut bool,
        visit: &mut impl FnMut(Record) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(record) = pending.take() {
            if record.valid && record.next == record.count {
                visit(Record::new(node, record.sequence, record.bytes))?;
            } else {
                *omitted = true;
            }
        }
        Ok(())
    }
    let mut previous_key: Option<Vec<u8>> = None;
    let mut pending: Option<Partial> = None;
    visit_journal_pages(calls, prefix, |page| {
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
                finish(node, &mut pending, omitted, &mut visit)?;
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
        Ok(())
    })?;
    finish(node, &mut pending, omitted, &mut visit)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    omitted: &mut bool,
) -> Result<bool, String> {
    let mut covered = false;
    fold_stored_records_observed(
        calls,
        current.node,
        current.node.to_be_bytes().to_vec(),
        omitted,
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
    // Cold multi-owner proofs deliberately do not acquire a fresh retry budget per owner.
    verify_stored_chain_once(calls, node, &[], None).map_err(ChainProofFailure::reason)
}

#[derive(Clone, Copy)]
struct GapWitness {
    node: u64,
    prefix_digest: [u8; 32],
    prefix_count: u64,
    before: ChainPoint,
    after: ChainPoint,
    tail: ChainPoint,
}

enum ChainProofFailure {
    Fatal(String),
    SequenceGap(GapWitness),
}
impl ChainProofFailure {
    fn reason(self) -> String {
        match self {
            Self::Fatal(reason) => reason,
            Self::SequenceGap(_) => {
                "the streamed Store journal has a broken hash link or sequence".into()
            }
        }
    }
}
impl From<String> for ChainProofFailure {
    fn from(reason: String) -> Self {
        Self::Fatal(reason)
    }
}

fn extend_chain_digest(digest: [u8; 32], point: ChainPoint) -> [u8; 32] {
    // Fixed-width, domain-separated canonical transcript; no historical bodies are retained.
    let mut bytes = [0u8; 160];
    let mut used = 0;
    for field in [
        b"busbar/journal/verified-prefix/v1\0".as_slice(),
        &digest,
        &point.node.to_be_bytes(),
        &point.sequence.to_be_bytes(),
        &point.hash,
        &point.previous,
    ] {
        bytes[used..used + field.len()].copy_from_slice(field);
        used += field.len();
    }
    busbar_kernel_wal::body_digest(&bytes[..used])
}

/// The sole retry belongs to this entire sealed-node proof. Original requested seals remain
/// immutable; OriginRead still checks its captured HEADs and fences after this returns.
pub(super) fn verify_stored_chain_with_seals(
    calls: &dyn StoreCalls,
    node: u64,
    seals: &[RecordSeal],
) -> Result<(), String> {
    match verify_stored_chain_once(calls, node, seals, None) {
        Ok(()) => Ok(()),
        Err(ChainProofFailure::Fatal(reason)) => Err(reason),
        Err(ChainProofFailure::SequenceGap(witness)) => {
            verify_stored_chain_once(calls, node, seals, Some(witness))
                .map_err(ChainProofFailure::reason)
        }
    }
}

fn verify_stored_chain_once(
    calls: &dyn StoreCalls,
    node: u64,
    seals: &[RecordSeal],
    retry: Option<GapWitness>,
) -> Result<(), ChainProofFailure> {
    if seals.iter().any(|seal| seal.node != node)
        || seals
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
    {
        return Err(ChainProofFailure::Fatal(
            "invalid same-read journal seal transcript".into(),
        ));
    }
    let mut matched = 0;
    let mut previous: Option<ChainPoint> = None;
    let mut digest = [0; 32];
    let mut count = 0u64;
    let mut gap = None;
    let mut omitted = false;
    let mut bridge_omitted = false;
    let mut prefix_matched = retry.is_none();
    let mut after_matched = retry.is_none();
    let mut tail_matched = retry.is_none();
    fold_stored_records_observed(
        calls,
        node,
        node.to_be_bytes().to_vec(),
        &mut omitted,
        |record| {
            let record = checked_record(record)?;
            let current = ChainPoint {
                node: record.node,
                sequence: record.node_seq,
                hash: record.hash,
                previous: record.prev_hash,
            };
            drop(record);
            if let Some(witness) = retry {
                if witness.node != node {
                    return Err("retry node differs".into());
                }
                if current.sequence == witness.after.sequence {
                    if current != witness.after {
                        return Err("retry gap boundary changed".into());
                    }
                    after_matched = true;
                }
                if current.sequence == witness.tail.sequence {
                    if current != witness.tail {
                        return Err("retry observed tail changed".into());
                    }
                    tail_matched = true;
                }
            }
            if let Some(before) = previous {
                let follows = current.previous == before.hash
                    && before.sequence.checked_add(1) == Some(current.sequence);
                // The original missing interval must now be filled by actual consecutive sealed
                // records. A newly observed quarantine note cannot substitute for gap fill.
                if retry.is_some_and(|witness| {
                    before.sequence >= witness.before.sequence
                        && before.sequence < witness.after.sequence
                }) && !follows
                {
                    return Err("retry did not fill the original sequence gap".into());
                }
                if !follows && !bridge_covers(calls, before, current, &mut bridge_omitted)? {
                    // Only a positive sequence gap between canonical validated records is eligible.
                    // Same-sequence/hash corruption and another mixed gap are never retried.
                    if retry.is_some()
                        || gap.is_some()
                        || before
                            .sequence
                            .checked_add(1)
                            .is_none_or(|next| current.sequence <= next)
                    {
                        return Err(
                            "the streamed Store journal has a broken hash link or sequence".into(),
                        );
                    }
                    gap = Some(GapWitness {
                        node,
                        prefix_digest: digest,
                        prefix_count: count,
                        before,
                        after: current,
                        tail: current,
                    });
                }
            }
            if let Some(seal) = seals.get(matched) {
                if seal.sequence < current.sequence {
                    return Err(
                        "a same-read recovery record is missing from its verified node".into(),
                    );
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
            digest = extend_chain_digest(digest, current);
            count = count
                .checked_add(1)
                .ok_or("journal prefix count overflow")?;
            if let Some(witness) = retry {
                if count == witness.prefix_count {
                    if digest != witness.prefix_digest || current != witness.before {
                        return Err("retry verified prefix changed".into());
                    }
                    prefix_matched = true;
                }
            }
            previous = Some(current);
            Ok(())
        },
    )?;
    if matched != seals.len() {
        return Err(ChainProofFailure::Fatal(
            "a same-read recovery record is missing from its verified node".into(),
        ));
    }
    if !prefix_matched || !after_matched || !tail_matched {
        return Err(ChainProofFailure::Fatal(
            "retry is missing its original prefix, boundary or tail".into(),
        ));
    }
    if let Some(mut witness) = gap {
        // Incomplete/malformed partials in this fold or its quarantine authority may not heal
        // into retryable absence, even if a later scan happens to return complete bytes.
        if omitted || bridge_omitted {
            return Err(ChainProofFailure::Fatal(
                "a torn journal record cannot authorize a gap retry".into(),
            ));
        }
        witness.tail = previous.expect("a gap has validated boundary records");
        return Err(ChainProofFailure::SequenceGap(witness));
    }
    if retry.is_some() && (omitted || bridge_omitted) {
        return Err(ChainProofFailure::Fatal(
            "a gap retry encountered a torn journal record".into(),
        ));
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
            let offered = {
                let mut state = self.lock();
                while state.queue.is_empty() && !state.stopped {
                    state = self.work.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                if state.queue.is_empty() || state.stopped && state.refusal.is_some() {
                    return;
                }
                let mut bytes = 0usize;
                let mut offered = Vec::new();
                for record in state.queue.iter().take(AUDIT_GROUP_RECORDS) {
                    let Some(next) = bytes.checked_add(record.body.len()) else {
                        break;
                    };
                    if !offered.is_empty()
                        && next as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES
                    {
                        break;
                    }
                    bytes = next;
                    offered.push(record.clone());
                }
                offered
            };
            let next = &offered[0];
            let attempted = prepare_audit_group(self.calls.as_ref(), &self.lease, &offered);
            let result = match attempted {
                Ok(Some(group)) => group
                    .commit(self.calls.as_ref(), &self.lease)
                    .map(|()| group.len()),
                Ok(None) => put_record(self.calls.as_ref(), &self.lease, next).map(|()| 1),
                Err(why) => Err(why),
            };
            match result {
                Ok(count) => {
                    pause = RETRY_FIRST;
                    let mut state = self.lock();
                    if !state
                        .queue
                        .iter()
                        .take(count)
                        .map(Record::identity)
                        .eq(offered[..count].iter().map(Record::identity))
                    {
                        state.refusal =
                            Some("committed audit group no longer matches the queue prefix".into());
                        state.stopped = true;
                        state.refusals = state.refusals.saturating_add(1);
                        self.set_full(&state);
                        self.moved.notify_all();
                        return;
                    }
                    for record in &offered[..count] {
                        state.queue.pop_front();
                        let mark = state.acked.entry(record.node).or_insert(0);
                        *mark = (*mark).max(record.node_seq);
                    }
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
