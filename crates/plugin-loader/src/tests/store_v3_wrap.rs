// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE TEST DOUBLE over the build's store: [`Wrapped<H>`] serves every store v3 op through
//! [`Hooks`], each hook defaulting to the memory store's own body, so a test overrides only the ops
//! it bends (a miscount, a shared backing, a settings check, a pend).

use std::marker::PhantomData;
use std::sync::Arc;

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, Grant, Op, OpResult, ReserveRefused, Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::both_ways::store_fixture::MemoryStore;

/// The ops a test bends; every default is the memory store's own.
#[allow(clippy::too_many_arguments)]
pub(crate) trait Hooks: Send + Sync + 'static {
    /// The settings check.
    fn validate(settings: &[u8]) -> Result<(), String> {
        <MemoryStore as StoreSlots>::validate(settings)
    }
    /// The backing store an open serves.
    fn open(settings: &[u8], host: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        let _ = (settings, host);
        Ok(Arc::new(MemoryStore::new()))
    }
    /// `open`'s connect step.
    fn connect(inner: &MemoryStore, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        let _ = (inner, cx);
        Step::Ready(Ok(()))
    }
    fn add_usage_op(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::add_usage_op(inner, cx, op, bucket, window_start, delta)
    }

    fn add_metering_op(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::add_metering_op(inner, cx, op, delta)
    }

    fn append_audit_op(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        entry: &AuditRecord,
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::append_audit_op(inner, cx, op, entry)
    }

    fn append_plane_record_op(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::append_plane_record_op(inner, cx, op, record)
    }

    fn append_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        <MemoryStore as StoreSlots>::append_batch(inner, cx, op, stream, records)
    }

    fn heads(inner: &MemoryStore, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        <MemoryStore as StoreSlots>::heads(inner, cx)
    }

    fn session_put(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        <MemoryStore as StoreSlots>::session_put(inner, cx, session, node, principal)
    }

    fn session_remove(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        session: u64,
    ) -> Step<Result<(), String>> {
        <MemoryStore as StoreSlots>::session_remove(inner, cx, session)
    }

    fn sessions_for(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        <MemoryStore as StoreSlots>::sessions_for(inner, cx, principal)
    }

    fn record_put(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        <MemoryStore as StoreSlots>::record_put(inner, cx, schema, key, value)
    }

    fn record_get(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        <MemoryStore as StoreSlots>::record_get(inner, cx, schema, key)
    }

    fn record_scan(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        <MemoryStore as StoreSlots>::record_scan(inner, cx, schema, prefix, limit)
    }

    fn reserve<'c>(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        <MemoryStore as StoreSlots>::reserve(inner, cx, op, epoch, cells, grants)
    }

    fn slice_release(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::slice_release(inner, cx, op, epoch, items, released)
    }

    fn add_usage_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::add_usage_batch(inner, cx, op, cells)
    }

    fn add_metering_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::add_metering_batch(inner, cx, op, deltas)
    }

    fn append_audit_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        <MemoryStore as StoreSlots>::append_audit_batch(inner, cx, op, entries)
    }

    fn window_caps(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        <MemoryStore as StoreSlots>::window_caps(inner, cx, op, caps)
    }

    fn put_key(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        key: &VirtualKey,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::put_key(inner, cx, key)
    }

    fn get_key(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        id: &str,
    ) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        <MemoryStore as StoreSlots>::get_key(inner, cx, id)
    }

    fn list_keys(inner: &MemoryStore, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        <MemoryStore as StoreSlots>::list_keys(inner, cx)
    }

    fn delete_key(inner: &MemoryStore, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::delete_key(inner, cx, id)
    }

    fn scrub_key(inner: &MemoryStore, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::scrub_key(inner, cx, id)
    }

    fn list_keys_since(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        <MemoryStore as StoreSlots>::list_keys_since(inner, cx, since)
    }

    fn get_usage(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        <MemoryStore as StoreSlots>::get_usage(inner, cx, bucket_id, window_start)
    }

    fn put_usage(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::put_usage(inner, cx, bucket_id, window_start, ledger)
    }

    fn list_metering(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        <MemoryStore as StoreSlots>::list_metering(inner, cx, bucket)
    }

    fn purge_windows_before(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        <MemoryStore as StoreSlots>::purge_windows_before(inner, cx, before)
    }

    fn purge_metering_before(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        bucket: &str,
    ) -> Step<RecordStoreResult<u64>> {
        <MemoryStore as StoreSlots>::purge_metering_before(inner, cx, bucket)
    }

    fn put_credential(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::put_credential(inner, cx, secret)
    }

    fn put_key_with_credential(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::put_key_with_credential(inner, cx, key, secret)
    }

    fn list_credentials(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        <MemoryStore as StoreSlots>::list_credentials(inner, cx, key_id)
    }

    fn lookup_credential_secret(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        <MemoryStore as StoreSlots>::lookup_credential_secret(inner, cx, kind, public_id)
    }

    fn revoke_credential(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::revoke_credential(inner, cx, id, reason)
    }

    fn list_credentials_since(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        <MemoryStore as StoreSlots>::list_credentials_since(inner, cx, since)
    }

    fn list_audit(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        <MemoryStore as StoreSlots>::list_audit(inner, cx)
    }

    fn add_denylist(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::add_denylist(inner, cx, sub, reason)
    }

    fn list_denylist(inner: &MemoryStore, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        <MemoryStore as StoreSlots>::list_denylist(inner, cx)
    }

    fn list_audit_tail(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        <MemoryStore as StoreSlots>::list_audit_tail(inner, cx, limit)
    }

    fn upsert_plane_record(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::upsert_plane_record(inner, cx, record)
    }

    fn get_plane_record(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        <MemoryStore as StoreSlots>::get_plane_record(inner, cx, kind, id)
    }

    fn list_plane_records(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        <MemoryStore as StoreSlots>::list_plane_records(inner, cx, kind, selector)
    }

    fn list_plane_record_parents(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        <MemoryStore as StoreSlots>::list_plane_record_parents(inner, cx, kind)
    }

    fn purge_plane_records_before(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        <MemoryStore as StoreSlots>::purge_plane_records_before(inner, cx, kind, before)
    }

    fn delete_plane_record(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        <MemoryStore as StoreSlots>::delete_plane_record(inner, cx, kind, id)
    }

    fn redeem_plane_token(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        <MemoryStore as StoreSlots>::redeem_plane_token(inner, cx, kind, token, expires_at, now)
    }

    fn plane_token_live(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        <MemoryStore as StoreSlots>::plane_token_live(inner, cx, kind, token, expires_at, now)
    }
}

/// The memory store, served through `H`.
pub(crate) struct Wrapped<H>(pub(crate) Arc<MemoryStore>, PhantomData<fn() -> H>);

#[allow(clippy::too_many_arguments)]
impl<H: Hooks> StoreSlots for Wrapped<H> {
    const TAIL: Tail = <MemoryStore as StoreSlots>::TAIL;

    fn validate(settings: &[u8]) -> Result<(), String> {
        H::validate(settings)
    }

    fn open(settings: &[u8], host: Option<Host>) -> Result<Self, String> {
        H::open(settings, host).map(|m| Self(m, PhantomData))
    }

    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        H::connect(&self.0, cx)
    }

    fn add_usage_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        H::add_usage_op(&self.0, cx, op, bucket, window_start, delta)
    }

    fn add_metering_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        H::add_metering_op(&self.0, cx, op, delta)
    }

    fn append_audit_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entry: &AuditRecord,
    ) -> Step<OpResult<()>> {
        H::append_audit_op(&self.0, cx, op, entry)
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        H::append_plane_record_op(&self.0, cx, op, record)
    }

    fn append_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        H::append_batch(&self.0, cx, op, stream, records)
    }

    fn heads(&self, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        H::heads(&self.0, cx)
    }

    fn session_put(
        &self,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        H::session_put(&self.0, cx, session, node, principal)
    }

    fn session_remove(&self, cx: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        H::session_remove(&self.0, cx, session)
    }

    fn sessions_for(
        &self,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        H::sessions_for(&self.0, cx, principal)
    }

    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        H::record_put(&self.0, cx, schema, key, value)
    }

    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        H::record_get(&self.0, cx, schema, key)
    }

    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        H::record_scan(&self.0, cx, schema, prefix, limit)
    }

    fn reserve<'c>(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        H::reserve(&self.0, cx, op, epoch, cells, grants)
    }

    fn slice_release(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        H::slice_release(&self.0, cx, op, epoch, items, released)
    }

    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        H::add_usage_batch(&self.0, cx, op, cells)
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        H::add_metering_batch(&self.0, cx, op, deltas)
    }

    fn append_audit_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        H::append_audit_batch(&self.0, cx, op, entries)
    }

    fn window_caps(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        H::window_caps(&self.0, cx, op, caps)
    }

    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        H::put_key(&self.0, cx, key)
    }

    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        H::get_key(&self.0, cx, id)
    }

    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        H::list_keys(&self.0, cx)
    }

    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        H::delete_key(&self.0, cx, id)
    }

    fn scrub_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        H::scrub_key(&self.0, cx, id)
    }

    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        H::list_keys_since(&self.0, cx, since)
    }

    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        H::get_usage(&self.0, cx, bucket_id, window_start)
    }

    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        H::put_usage(&self.0, cx, bucket_id, window_start, ledger)
    }

    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        H::list_metering(&self.0, cx, bucket)
    }

    fn purge_windows_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        H::purge_windows_before(&self.0, cx, before)
    }

    fn purge_metering_before(&self, cx: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        H::purge_metering_before(&self.0, cx, bucket)
    }

    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        H::put_credential(&self.0, cx, secret)
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        H::put_key_with_credential(&self.0, cx, key, secret)
    }

    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        H::list_credentials(&self.0, cx, key_id)
    }

    fn lookup_credential_secret(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        H::lookup_credential_secret(&self.0, cx, kind, public_id)
    }

    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        H::revoke_credential(&self.0, cx, id, reason)
    }

    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        H::list_credentials_since(&self.0, cx, since)
    }

    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        H::list_audit(&self.0, cx)
    }

    fn add_denylist(
        &self,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        H::add_denylist(&self.0, cx, sub, reason)
    }

    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        H::list_denylist(&self.0, cx)
    }

    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        H::list_audit_tail(&self.0, cx, limit)
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        H::upsert_plane_record(&self.0, cx, record)
    }

    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        H::get_plane_record(&self.0, cx, kind, id)
    }

    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        H::list_plane_records(&self.0, cx, kind, selector)
    }

    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        H::list_plane_record_parents(&self.0, cx, kind)
    }

    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        H::purge_plane_records_before(&self.0, cx, kind, before)
    }

    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        H::delete_plane_record(&self.0, cx, kind, id)
    }

    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        H::redeem_plane_token(&self.0, cx, kind, token, expires_at, now)
    }

    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        H::plane_token_live(&self.0, cx, kind, token, expires_at, now)
    }
}
