// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`StoreSlots`]): the
//! `op_id`-carrying count batches, plane records and the kernel-held records. It holds no money:
//! money is counts x the rate card, derived in busbar's core.
//!
//! DEDUPE (`abi::store` S1-S4): every `op_id` this store APPLIED is remembered, with a SHA-256
//! digest of the op's value fields and its answer, for [`OP_ID_RETENTION_SECS`]. The digest is fixed
//! size, so what the log keeps per op does not grow with what the op wrote. A replay with the same
//! value fields applies nothing and answers the original; different value fields are a conflict.
//! The dedupe log lives under ONE lock, and an op's dedupe check, its effect and its record happen
//! under it, so two racing calls with one `op_id` apply once. This store is EPHEMERAL (its
//! Statement tail says so): the log is lost on restart together with everything it guards, so a
//! replay after a restart re-applies onto an empty store, which is the state the restart left.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreResult, Retention, UsageDelta, UsageLedger, VirtualKey,
};

use crate::MemoryStore;

busbar_contract::store_door!(MemoryStore, "memory", env!("CARGO_PKG_VERSION"), 1024);

/// What an applied op answered, replayed verbatim.
#[derive(Debug, Clone)]
enum Answer {
    Done,
}

/// The SHA-256 digest of an op's value fields, as their text renders them.
type Body = [u8; 32];

/// A [`std::fmt::Write`] that feeds what is written into a digest, so the text is never held.
struct Feed(sha2::Sha256);

impl std::fmt::Write for Feed {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        sha2::Digest::update(&mut self.0, s.as_bytes());
        Ok(())
    }
}

/// The [`Body`] of the value fields `args` render.
fn body(args: std::fmt::Arguments<'_>) -> Body {
    let mut feed = Feed(<sha2::Sha256 as sha2::Digest>::new());
    // Writing into a digest cannot fail.
    let _ = feed.write_fmt(args);
    sha2::Digest::finalize(feed.0).into()
}

/// One remembered op: the digest of its value fields and its answer.
struct Recorded {
    body: Body,
    answer: Answer,
}

#[derive(Default)]
struct Inner {
    ops: HashMap<OpId, Recorded>,
    /// `(recorded_at, op_id)`, oldest first: the retention sweep's order.
    aged: VecDeque<(u64, OpId)>,
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
    fn seen(&self, op: OpId, body: &Body) -> Seen {
        match self.ops.get(&op) {
            None => Seen::New,
            Some(r) if r.body == *body => Seen::Replay(r.answer.clone()),
            Some(_) => Seen::Conflict,
        }
    }

    /// Remember an APPLIED op, and forget every op past its retention.
    fn record(&mut self, now: u64, op: OpId, body: Body, answer: Answer) {
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

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

impl MemoryStore {
    /// Run one `op_id`-carrying write under the v3 lock: a replay answers the original, a
    /// conflict applies nothing, and a new op runs `apply` and is remembered only if it applied.
    fn deduped(
        &self,
        op: OpId,
        body: Body,
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
}

/// The store v3 slots' own bodies: each op's ONE body, which the table's slot answers inline (the
/// memory store never pends).
impl MemoryStore {
    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        let body = body(format_args!("append_plane_record:{:?}", record.to_record()));
        self.deduped(op, body, |s, _| {
            s.append_plane_record(record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
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

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let body = body(format_args!("add_usage_batch:{cells:?}"));
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
        let body = body(format_args!("add_metering_batch:{deltas:?}"));
        self.deduped(op, body, |s, _| {
            for d in deltas {
                s.add_metering(d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
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

    fn append_plane_record_op(
        &self,
        _: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        Step::Ready(self.v3_append_plane_record_op(op, record))
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

    fn purge_usage_before(&self, _: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        let mut usage = self.usage();
        let was = usage.len();
        usage.retain(|(_, window_start), _| *window_start == 0 || *window_start >= before);
        Step::Ready(Ok((was - usage.len()) as u64))
    }

    fn purge_plane_records(
        &self,
        _: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> Step<RecordStoreResult<u64>> {
        Step::Ready(RecordStore::purge_plane_records(
            self, kind, before, retention,
        ))
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
