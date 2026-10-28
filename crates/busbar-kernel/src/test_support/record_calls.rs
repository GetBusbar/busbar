// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST DOUBLE'S 1.5.5 OP SET, SERVED AS [`StoreCalls`]: a kernel cell whose store double
//! implements the plugin-side [`RecordStore`] (a store that fails one op, parks one crossing,
//! keeps a legacy audit table, …) hands it to a consumer of the host's one store seam by wrapping
//! it here. Every call runs the double's own method when it is made and answers at once; a
//! double's error is a FAILED op carrying its text, which a consumer reads back verbatim, as it
//! reads a loaded store's. The `op_id` of an additive write is not the double's to see: the 1.5.5
//! op set carries none.

use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreResult, UsageDelta, VirtualKey,
};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

/// `store`'s 1.5.5 op set as [`StoreCalls`] (see the module doc).
pub struct RecordCalls(pub Arc<dyn RecordStore>);

impl RecordCalls {
    /// `store`, wrapped and shared.
    #[must_use]
    pub fn over(store: Arc<dyn RecordStore>) -> Arc<dyn StoreCalls> {
        Arc::new(Self(store))
    }
}

/// One answer, in hand: a double's error is FAILED with its text.
fn ready<'a, T: Send + 'a>(answer: RecordStoreResult<T>) -> StoreCall<'a, T> {
    Box::pin(std::future::ready(
        answer.map_err(|e| StoreFailure::Failed(e.0)),
    ))
}

impl StoreCalls for RecordCalls {
    fn add_usage_batch<'a>(
        &'a self,
        _op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        ready(
            cells
                .iter()
                .try_for_each(|(bucket, window, delta)| self.0.add_usage(bucket, *window, delta)),
        )
    }

    fn add_metering_batch<'a>(
        &'a self,
        _op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        ready(deltas.iter().try_for_each(|d| self.0.add_metering(d)))
    }

    fn record_put<'a>(
        &'a self,
        _schema: &'a str,
        _key: &'a [u8],
        _value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        Box::pin(std::future::ready(Err(StoreFailure::Refused(
            "a 1.5.5 store keeps no kernel-held records".to_string(),
        ))))
    }

    fn record_get<'a>(
        &'a self,
        _schema: &'a str,
        _key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        ready(Ok(None))
    }

    fn record_scan<'a>(
        &'a self,
        _schema: &'a str,
        _prefix: &'a [u8],
        _limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        ready(Ok(Vec::new()))
    }

    fn put_key<'a>(&'a self, key: &'a VirtualKey) -> StoreCall<'a, ()> {
        ready(self.0.put_key(key))
    }

    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<VirtualKey>> {
        ready(self.0.get_key(id))
    }

    fn list_keys(&self) -> StoreCall<'_, Vec<VirtualKey>> {
        ready(self.0.list_keys())
    }

    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        ready(self.0.delete_key(id))
    }

    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a VirtualKey,
        secret: &'a CredentialSecret,
    ) -> StoreCall<'a, ()> {
        ready(self.0.put_key_with_credential(key, secret))
    }

    fn list_credentials<'a>(&'a self, key_id: &'a str) -> StoreCall<'a, Vec<CredentialMeta>> {
        ready(self.0.list_credentials(key_id))
    }

    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        ready(self.0.revoke_credential(id, reason))
    }

    fn list_credentials_since(&self, since: u64) -> StoreCall<'_, Vec<CredentialSecret>> {
        ready(self.0.list_credentials_since(since))
    }

    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        ready(self.0.add_denylist(sub, reason))
    }

    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        ready(self.0.list_denylist())
    }

    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<MeteringRow>> {
        ready(self.0.list_metering(bucket))
    }

    fn list_audit(&self) -> StoreCall<'_, Vec<AuditRecord>> {
        ready(self.0.list_audit())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<AuditRecord>> {
        ready(self.0.list_audit_tail(limit))
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        ready(self.0.upsert_plane_record(record))
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        ready(self.0.get_plane_record(kind, id))
    }

    fn append_plane_record<'a>(
        &'a self,
        _op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        ready(self.0.append_plane_record(record))
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        ready(self.0.list_plane_records(kind, selector))
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        ready(self.0.delete_plane_record(kind, id))
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        ready(self.0.redeem_plane_token(kind, token, expires_at, now))
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        ready(self.0.plane_token_live(kind, token, expires_at, now))
    }

    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        ready(self.0.list_plane_record_parents(kind))
    }

    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        ready(self.0.purge_plane_records_before(kind, before))
    }
}
