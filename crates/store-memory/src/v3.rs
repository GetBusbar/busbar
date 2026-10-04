// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`StoreSlots`]): the
//! `op_id`-carrying writes, the ledger ops, the money slots and `window_caps`.
//!
//! DEDUPE (`abi::store` S1-S4): every `op_id` this store APPLIED is remembered, with the op's value
//! fields and its answer, for [`OP_ID_RETENTION_SECS`]. A replay with the same value fields applies
//! nothing and answers the original; different value fields are a conflict. The dedupe log, the
//! caps, the drawn totals and the slices live under ONE lock, and an op's dedupe check, its effect
//! and its record happen under it, so two racing calls with one `op_id` apply once. This store is
//! EPHEMERAL (its Statement tail says so): the log is lost on restart together with everything it
//! guards, so a replay after a restart re-applies onto an empty store, which is the state the
//! restart left.
//!
//! EPOCH AND SLICE LIFE (`abi::store::SLICE_TTL_MS`, the store kind's spec): this is a NODE-LOCAL
//! store, and its rule holds for a SINGLE node only. It holds one constant epoch, never answers a
//! stale one (the `epoch` a caller states is accepted as given) and grants slices that never expire
//! (`valid_until_ms = u64::MAX`): no other node can draw against its windows. A store a fleet shares
//! persists and fences the epoch and bounds every slice. A release, here as everywhere, returns at
//! most what the slice has left, and a slice with nothing left returns `0`.
//!
//! GRANT SIZE: a cell grants its whole `amount` or the reserve fails; the per-dimension test
//! is 1.5.5's, cited on `abi::store::ReserveIn`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::MemoryStore;

busbar_contract::store_door!(MemoryStore, "memory", env!("CARGO_PKG_VERSION"), 1024);

/// A slot key owned by the store: `(bucket, pool, dimension, class_key, window_start)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Slot {
    bucket: String,
    pool: Option<String>,
    dimension: u32,
    class_key: String,
    window_start: u64,
}

impl Slot {
    fn of(k: &CellKey<'_>) -> Self {
        let (dimension, class_key) = match k.dimension {
            Dimension::NanoUnits => (0, ""),
            Dimension::Requests => (1, ""),
            Dimension::Concurrency => (2, ""),
            Dimension::Class(c) => (3, c),
        };
        Self {
            bucket: k.bucket.to_string(),
            pool: k.pool.map(str::to_string),
            dimension,
            class_key: class_key.to_string(),
            window_start: k.window_start,
        }
    }
}

/// What an applied op answered, replayed verbatim.
#[derive(Debug, Clone)]
enum Answer {
    Done,
    Head(Head),
    Grants(Vec<Grant>),
    Released(Vec<u64>),
}

/// One remembered op: its value fields and its answer.
struct Recorded {
    body: String,
    answer: Answer,
}

/// A drawn slice: the slot it drew from and what it still holds.
struct Drawn {
    slot: Slot,
    left: u64,
}

#[derive(Default)]
struct Inner {
    ops: HashMap<OpId, Recorded>,
    /// `(recorded_at, op_id)`, oldest first: the retention sweep's order.
    aged: VecDeque<(u64, OpId)>,
    /// `slot -> (cap, config_gen)`.
    caps: HashMap<Slot, (u64, u64)>,
    /// `slot -> drawn and not released`.
    used: HashMap<Slot, u64>,
    slices: HashMap<u64, Drawn>,
    /// The slices whose unreturned unspent reached `0`, with when: a later release of one returns
    /// `0`. Kept as long as an `op_id` is (`OP_ID_RETENTION_SECS`), then forgotten.
    closed: HashMap<u64, u64>,
    next_slice: u64,
    /// `stream -> its records`; the head's `seq` is the count.
    journals: HashMap<String, Vec<RecordBytes>>,
    /// `session -> (node, principal)`.
    sessions: HashMap<u64, (String, String)>,
}

/// The v3 state [`MemoryStore`] carries.
#[derive(Default)]
pub(crate) struct State {
    inner: Mutex<Inner>,
}

/// Whether an op is new, a replay, or a conflict.
enum Seen {
    New,
    Replay(Answer),
    Conflict,
}

impl Inner {
    fn seen(&self, op: OpId, body: &str) -> Seen {
        match self.ops.get(&op) {
            None => Seen::New,
            Some(r) if r.body == body => Seen::Replay(r.answer.clone()),
            Some(_) => Seen::Conflict,
        }
    }

    /// Remember an APPLIED op, and forget every op past its retention.
    fn record(&mut self, now: u64, op: OpId, body: String, answer: Answer) {
        while let Some(&(at, old)) = self.aged.front() {
            if at.saturating_add(OP_ID_RETENTION_SECS) > now {
                break;
            }
            self.aged.pop_front();
            self.ops.remove(&old);
        }
        self.ops.insert(op, Recorded { body, answer });
        self.aged.push_back((now, op));
    }
}

impl State {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The 1.5.5 admission test for one cell (`abi::store::ReserveIn`, GRANT SIZE): whether drawing
/// `amount` onto `used` under `cap` is refused. `used + amount` is checked: an overflow refuses.
fn exhausted(dimension: u32, used: u64, amount: u64, cap: u64) -> bool {
    let Some(after) = used.checked_add(amount) else {
        return true;
    };
    match dimension {
        // DIM_CLASS: `tokens >= cap` — the draw that crosses the cap is granted whole.
        3 => used >= cap,
        // DIM_NANO_UNITS: `derived >= cap || derived + fee > cap`.
        0 => used >= cap || after > cap,
        // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
        _ => after > cap,
    }
}

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

impl MemoryStore {
    /// Run one `op_id`-carrying write under the v3 lock: a replay answers the original, a
    /// conflict applies nothing, and a new op runs `apply` and is remembered only if it applied.
    fn deduped(
        &self,
        op: OpId,
        body: String,
        apply: impl FnOnce(&Self, &mut Inner) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        let mut inner = self.v3.lock();
        match inner.seen(op, &body) {
            Seen::Replay(a) => Ok(a),
            Seen::Conflict => Err(OpRefused::Conflict),
            Seen::New => {
                let answer = apply(self, &mut inner)?;
                inner.record(self.now(), op, body, answer.clone());
                Ok(answer)
            }
        }
    }

    /// Every audit record in `entries` would append (none forks a stored `seq`, nor another in the
    /// batch), checked before any is applied.
    fn audit_fits(&self, entries: &[AuditRecord]) -> OpResult<()> {
        let audit = self.audit.read().unwrap_or_else(|e| e.into_inner());
        let mut batch: HashMap<u64, &AuditRecord> = HashMap::new();
        for e in entries {
            let prior = audit.get(&e.seq).or_else(|| batch.get(&e.seq).copied());
            if prior.is_some_and(|p| p != e) {
                return Err(OpRefused::Failed(format!(
                    "append_audit: seq {} already holds a DIFFERENT record — the audit chain has forked",
                    e.seq
                )));
            }
            batch.insert(e.seq, e);
        }
        Ok(())
    }
}

/// The store v3 slots' own bodies: each op's ONE body, which the table's slot answers inline (the
/// memory store never pends).
impl MemoryStore {
    pub(crate) fn v3_add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        self.deduped(op, body, |s, _| {
            s.add_usage(bucket, window_start, delta).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.deduped(op, body, |s, _| {
            s.add_metering(delta).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.deduped(op, body, |s, _| {
            s.append_audit(entry).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        let body = format!("append_plane_record:{:?}", record.to_record());
        self.deduped(op, body, |s, _| {
            s.append_plane_record(record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_append_batch(
        &self,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let answer = self.deduped(op, body, |_, inner| {
            let rows = inner.journals.entry(stream.to_string()).or_default();
            rows.extend(records.iter().cloned());
            Ok(Answer::Head(Head {
                seq: rows.len() as u64,
                epoch: 0,
            }))
        })?;
        match answer {
            Answer::Head(h) => Ok(h),
            _ => Err(OpRefused::Conflict),
        }
    }

    pub(crate) fn v3_heads(&self) -> Result<Vec<(String, Head)>, String> {
        let inner = self.v3.lock();
        let mut heads: Vec<(String, Head)> = inner
            .journals
            .iter()
            .map(|(s, rows)| {
                (
                    s.clone(),
                    Head {
                        seq: rows.len() as u64,
                        epoch: 0,
                    },
                )
            })
            .collect();
        heads.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(heads)
    }

    pub(crate) fn v3_session_put(
        &self,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Result<(), String> {
        self.v3
            .lock()
            .sessions
            .insert(session, (node.to_string(), principal.to_string()));
        Ok(())
    }

    pub(crate) fn v3_session_remove(&self, session: u64) -> Result<(), String> {
        self.v3.lock().sessions.remove(&session);
        Ok(())
    }

    pub(crate) fn v3_sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let inner = self.v3.lock();
        let mut rows: Vec<(u64, String)> = inner
            .sessions
            .iter()
            .filter(|(_, (_, p))| p == principal)
            .map(|(s, (n, _))| (*s, n.clone()))
            .collect();
        rows.sort_unstable();
        Ok(rows)
    }

    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        // The store keeps the record, so it copies it here (the door lends the host's bytes).
        let value = RecordBytes::new(value.to_vec())
            .map_err(|n| format!("a record of {n} bytes is over the ceiling"))?;
        self.record_put_at(schema, key, &value);
        Ok(())
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        Ok(self.record_get_at(schema, key))
    }

    pub(crate) fn v3_record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        Ok(self.record_scan_at(schema, prefix, limit))
    }

    pub(crate) fn v3_reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let mut inner = self.v3.lock();
        match inner.seen(op, &body) {
            Seen::Replay(Answer::Grants(g)) => {
                grants.extend(g);
                return Ok(());
            }
            Seen::Replay(_) | Seen::Conflict => return Err(ReserveRefused::Conflict),
            Seen::New => {}
        }
        // The chain draw is all or nothing: test every cell against what the cells before it in
        // THIS draw add, and apply only when every cell passes.
        let mut drawn: HashMap<Slot, u64> = HashMap::new();
        let mut slots = Vec::with_capacity(cells.len());
        for (i, c) in cells.iter().enumerate() {
            let slot = Slot::of(&c.key);
            let Some(&(cap, _)) = inner.caps.get(&slot) else {
                return Err(ReserveRefused::NoCap { cell: i as u32 });
            };
            let used = inner.used.get(&slot).copied().unwrap_or(0);
            let used = used.saturating_add(drawn.get(&slot).copied().unwrap_or(0));
            if exhausted(slot.dimension, used, c.amount, cap) {
                return Err(ReserveRefused::Exhausted { cell: i as u32 });
            }
            *drawn.entry(slot.clone()).or_default() += c.amount;
            slots.push(slot);
        }
        let mut granted = Vec::with_capacity(cells.len());
        for (c, slot) in cells.iter().zip(slots) {
            inner.next_slice += 1;
            let slice_id = inner.next_slice;
            let used = inner.used.entry(slot.clone()).or_default();
            *used = used.saturating_add(c.amount);
            inner.slices.insert(
                slice_id,
                Drawn {
                    slot,
                    left: c.amount,
                },
            );
            granted.push(Grant {
                slice_id,
                granted: c.amount,
                // Single node: nothing expires a slice no other node can draw against.
                valid_until_ms: u64::MAX,
            });
        }
        grants.extend(granted.iter().copied());
        inner.record(self.now(), op, body, Answer::Grants(granted));
        Ok(())
    }

    pub(crate) fn v3_slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let now = self.now();
        let answer = self.deduped(op, body, |_, inner| {
            if inner.closed.len() > 1024 {
                inner
                    .closed
                    .retain(|_, at| at.saturating_add(OP_ID_RETENTION_SECS) > now);
            }
            let known = |id: &u64| inner.slices.contains_key(id) || inner.closed.contains_key(id);
            if let Some((id, _)) = items.iter().find(|(id, _)| !known(id)) {
                return Err(OpRefused::Failed(format!(
                    "slice_release: slice {id} was never granted"
                )));
            }
            let mut back_all = Vec::with_capacity(items.len());
            for &(id, unspent) in &items {
                // A slice closed once its unreturned unspent reached 0 (by an earlier release, or an
                // earlier item of this call) returns nothing more.
                let Some(d) = inner.slices.get_mut(&id) else {
                    back_all.push(0);
                    continue;
                };
                let back = unspent.min(d.left);
                d.left -= back;
                let slot = d.slot.clone();
                if d.left == 0 {
                    inner.slices.remove(&id);
                    inner.closed.insert(id, now);
                }
                if let Some(u) = inner.used.get_mut(&slot) {
                    *u = u.saturating_sub(back);
                }
                back_all.push(back);
            }
            Ok(Answer::Released(back_all))
        })?;
        match answer {
            Answer::Released(r) => {
                released.extend(r);
                Ok(())
            }
            _ => Err(OpRefused::Conflict),
        }
    }

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        self.deduped(op, body, |s, _| {
            // A RAM ledger cannot fail an add, so applying in order is atomic.
            for (bucket, window, delta) in cells {
                s.add_usage(bucket, *window, delta).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.deduped(op, body, |s, _| {
            for d in deltas {
                s.add_metering(d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        self.deduped(op, body, |s, _| {
            s.audit_fits(entries)?;
            for e in entries {
                s.append_audit(e).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        let mut inner = self.v3.lock();
        match inner.seen(op, &body) {
            Seen::Replay(_) => return Ok(()),
            Seen::Conflict => return Err(CapsRefused::Conflict),
            Seen::New => {}
        }
        // Atomic per push: find the first conflict before applying any cap.
        let mut pushed: HashMap<Slot, (u64, u64)> = HashMap::new();
        for (index, c) in caps.iter().enumerate() {
            let slot = Slot::of(&c.key);
            let stored = pushed.get(&slot).or_else(|| inner.caps.get(&slot)).copied();
            match stored {
                Some((cap, gen)) if gen == c.config_gen && cap != c.cap => {
                    return Err(CapsRefused::CapConflict { index });
                }
                Some((_, gen)) if gen >= c.config_gen => {}
                _ => {
                    pushed.insert(slot, (c.cap, c.config_gen));
                }
            }
        }
        inner.caps.extend(pushed);
        inner.record(self.now(), op, body, Answer::Done);
        Ok(())
    }
}

impl StoreSlots for MemoryStore {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn validate(_settings: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn open(_settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        Ok(Self::new())
    }

    fn add_usage_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_usage_op(op, bucket, window_start, delta))
    }

    fn add_metering_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_metering_op(op, delta))
    }

    fn append_audit_op(&self, _: &mut Op<'_>, op: OpId, entry: &AuditRecord) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_audit_op(op, entry))
    }

    fn append_plane_record_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_plane_record_op(op, record))
    }

    fn append_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        Step::Ready(self.v3_append_batch(op, stream, records))
    }

    fn heads(&self, _: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        Step::Ready(self.v3_heads())
    }

    fn session_put(
        &self,
        _: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        Step::Ready(self.v3_session_put(session, node, principal))
    }

    fn session_remove(&self, _: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        Step::Ready(self.v3_session_remove(session))
    }

    fn sessions_for(
        &self,
        _: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        Step::Ready(self.v3_sessions_for(principal))
    }

    fn record_put(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        Step::Ready(self.v3_record_put(schema, key, value))
    }

    fn record_get(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        Step::Ready(self.v3_record_get(schema, key))
    }

    fn record_scan(
        &self,
        _: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        Step::Ready(self.v3_record_scan(schema, prefix, limit))
    }

    fn reserve<'c>(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        Step::Ready(self.v3_reserve(op, epoch, cells, grants))
    }

    fn slice_release(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_slice_release(op, epoch, items, released))
    }

    fn add_usage_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_usage_batch(op, cells))
    }

    fn add_metering_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_add_metering_batch(op, deltas))
    }

    fn append_audit_batch(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_audit_batch(op, entries))
    }

    fn window_caps(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        Step::Ready(self.v3_window_caps(op, caps))
    }

    fn put_key(&self, _: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_key(self, key))
    }

    fn get_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        Step::Ready(RecordStore::get_key(self, id))
    }

    fn list_keys(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        Step::Ready(RecordStore::list_keys(self))
    }

    fn delete_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::delete_key(self, id))
    }

    fn scrub_key(&self, _: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::scrub_key(self, id))
    }

    fn list_keys_since(
        &self,
        _: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        Step::Ready(RecordStore::list_keys_since(self, since))
    }

    fn get_usage(
        &self,
        _: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        Step::Ready(RecordStore::get_usage(self, bucket_id, window_start))
    }

    fn put_usage(
        &self,
        _: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_usage(
            self,
            bucket_id,
            window_start,
            ledger,
        ))
    }

    fn list_metering(
        &self,
        _: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        Step::Ready(RecordStore::list_metering(self, bucket))
    }

    fn purge_windows_before(&self, _: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_windows_before(self, before))
    }

    fn purge_metering_before(&self, _: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_metering_before(self, bucket))
    }

    fn put_credential(
        &self,
        _: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_credential(self, secret))
    }

    fn put_key_with_credential(
        &self,
        _: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::put_key_with_credential(self, key, secret))
    }

    fn list_credentials(
        &self,
        _: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        Step::Ready(RecordStore::list_credentials(self, key_id))
    }

    fn lookup_credential_secret(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        Step::Ready(RecordStore::lookup_credential_secret(self, kind, public_id))
    }

    fn revoke_credential(
        &self,
        _: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::revoke_credential(self, id, reason))
    }

    fn list_credentials_since(
        &self,
        _: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        Step::Ready(RecordStore::list_credentials_since(self, since))
    }

    fn list_audit(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        Step::Ready(RecordStore::list_audit(self))
    }

    fn add_denylist(&self, _: &mut Op<'_>, sub: &str, reason: &str) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::add_denylist(self, sub, reason))
    }

    fn list_denylist(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        Step::Ready(RecordStore::list_denylist(self))
    }

    fn list_audit_tail(
        &self,
        _: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        Step::Ready(RecordStore::list_audit_tail(self, limit))
    }

    fn upsert_plane_record(
        &self,
        _: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::upsert_plane_record(self, record))
    }

    fn get_plane_record(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        Step::Ready(RecordStore::get_plane_record(self, kind, id))
    }

    fn list_plane_records(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        Step::Ready(RecordStore::list_plane_records(self, kind, selector))
    }

    fn list_plane_record_parents(
        &self,
        _: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        Step::Ready(RecordStore::list_plane_record_parents(self, kind))
    }

    fn purge_plane_records_before(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_plane_records_before(self, kind, before))
    }

    fn delete_plane_record(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        Step::Ready(RecordStore::delete_plane_record(self, kind, id))
    }

    fn redeem_plane_token(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        Step::Ready(RecordStore::redeem_plane_token(
            self, kind, token, expires_at, now,
        ))
    }

    fn plane_token_live(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        Step::Ready(RecordStore::plane_token_live(
            self, kind, token, expires_at, now,
        ))
    }
}
