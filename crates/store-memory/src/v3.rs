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
//! EPOCH: a node-local store holds one constant epoch and never answers a stale one (`ReserveIn`'s
//! doc, "A node-local store"), so the `epoch` a caller states is accepted as given.
//!
//! GRANT SIZE: a cell grants its whole `amount` or the reserve fails; the per-dimension test
//! is 1.5.5's, cited on `abi::store::ReserveIn`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, MeteringDelta, PlaneRecord, RecordStore, UsageDelta};

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

impl StoreSlots for MemoryStore {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn open(_settings: &[u8]) -> Result<Self, String> {
        Ok(Self::new())
    }

    fn add_usage_op(
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

    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.deduped(op, body, |s, _| {
            s.add_metering(delta).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.deduped(op, body, |s, _| {
            s.append_audit(entry).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    fn append_plane_record_op(&self, op: OpId, record: &PlaneRecord) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        self.deduped(op, body, |s, _| {
            s.append_plane_record(record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
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

    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
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

    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        self.v3
            .lock()
            .sessions
            .insert(session, (node.to_string(), principal.to_string()));
        Ok(())
    }

    fn session_remove(&self, session: u64) -> Result<(), String> {
        self.v3.lock().sessions.remove(&session);
        Ok(())
    }

    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
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

    fn record_put(&self, schema: &str, key: &[u8], value: &RecordBytes) -> Result<(), String> {
        self.record_put_at(schema, key, value);
        Ok(())
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        Ok(self.record_get_at(schema, key))
    }

    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        Ok(self.record_scan_at(schema, prefix, limit))
    }

    fn reserve<'c>(
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
                // Nothing expires a slice that no other node can draw against.
                valid_until_ms: u64::MAX,
            });
        }
        grants.extend(granted.iter().copied());
        inner.record(self.now(), op, body, Answer::Grants(granted));
        Ok(())
    }

    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let answer = self.deduped(op, body, |_, inner| {
            if let Some((id, _)) = items.iter().find(|(id, _)| !inner.slices.contains_key(id)) {
                return Err(OpRefused::Failed(format!(
                    "slice_release: slice {id} is not held"
                )));
            }
            let mut back_all = Vec::with_capacity(items.len());
            for &(id, unspent) in &items {
                let Some(d) = inner.slices.get_mut(&id) else {
                    // An item naming a slice an EARLIER item of this call closed.
                    back_all.push(0);
                    continue;
                };
                let back = unspent.min(d.left);
                d.left -= back;
                let slot = d.slot.clone();
                if d.left == 0 {
                    inner.slices.remove(&id);
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

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
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

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.deduped(op, body, |s, _| {
            for d in deltas {
                s.add_metering(d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
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

    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
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
