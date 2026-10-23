// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the migration's head read does with a store that will not answer.

use super::*;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore as AbiStore, RecordStoreError, RecordStoreResult, Retention,
    UsageDelta, UsageLedger, VirtualKey,
};

/// A store that answers the audit tail however the test says and holds nothing else.
///
/// `Ok(Vec::new())` is what a store which does not KNOW the tail op reads as by the time the
/// adapter sees it: the loaded-store seam already turns the plugin's out-of-band
/// "I cannot decode this request" into the empty list, so an old store and an empty log are the
/// same answer here — which is the point. `Err` is the case that is NOT the same: a store that
/// failed to answer.
struct AuditTail(Result<Vec<AuditRecord>, String>);

impl AbiStore for AuditTail {
    fn put_key(&self, _key: &VirtualKey) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _bucket_id: &str, _window_start: u64) -> RecordStoreResult<UsageLedger> {
        Ok(UsageLedger::default())
    }
    fn add_metering(&self, _delta: &MeteringDelta) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _l: &UsageLedger,
    ) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_audit_tail(&self, _limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.0.clone().map_err(RecordStoreError)
    }
    fn scrub_key(&self, _id: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support scrub_key".to_string(),
        ))
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(AbiStore::list_keys(self)?
            .into_iter()
            .filter(|k| k.revision == 0 || k.revision > since)
            .collect())
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let mut cur = AbiStore::get_usage(self, bucket_id, window_start)?;
        cur.apply_delta(delta);
        AbiStore::put_usage(self, bucket_id, window_start, &cur)
    }
    fn purge_windows_before(&self, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_metering_before(&self, _bucket: &str) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        AbiStore::put_key(self, key)?;
        AbiStore::put_credential(self, secret)?;
        Ok(())
    }
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }
    fn lookup_credential_secret(
        &self,
        _kind: &str,
        _public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(None)
    }
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }
    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        Ok(Vec::new())
    }
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        match retention {
            Retention::Age => AbiStore::purge_plane_records_before(self, kind, before),
            Retention::TerminalOnly => Ok(0),
        }
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

/// An adapter over a store whose audit tail answers `tail`.
fn adapter_over_tail(tail: Result<Vec<AuditRecord>, String>) -> StoreAdapter {
    StoreAdapter::new(
        Arc::new(AuditTail(tail)),
        busbar_contract::abi::store::ABI_VERSION,
    )
}

/// One audit row, at a named sequence number.
fn record(seq: u64) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 0,
        action: "key.create".to_string(),
        resource: String::new(),
        outcome: "applied".to_string(),
        principal: String::new(),
        prev_hash: String::new(),
        hash: format!("hash-{seq}"),
    }
}

/// A store that will not answer for its audit rows has not said "there are none". The head is
/// still empty — a node whose store is briefly unreachable must boot — but the reason is named, so
/// the migration report says the chain head is unknown instead of silently sealing over it.
#[test]
fn a_store_that_will_not_answer_for_its_audit_tail_names_the_reason() {
    let adapter = adapter_over_tail(Err("the backend is unreachable".to_string()));
    let read = adapter.legacy_audit_head();
    assert_eq!(read.head, LegacyHead::empty(), "an unread head is empty");
    let reason = read
        .unreadable
        .expect("a store that would not answer must name the reason it did not");
    assert!(
        reason.contains("the backend is unreachable"),
        "the reason must carry what the store said, said: {reason}"
    );

    // And it reaches the migration report on the same channel an unread cell does.
    let rows = adapter.legacy_ledger_rows(LegacyReadPlan::nothing());
    assert_eq!(
        rows.read_figures().unreadable.len(),
        1,
        "the unread head joins the unread cells the report already prints"
    );
}

/// A store that answers with no rows — because it keeps none, or because it predates the tail op
/// and the loaded-store seam already read that as "no durable audit" — has answered. The head is
/// empty and nothing is reported, exactly as before.
#[test]
fn a_store_with_no_audit_rows_reads_empty_without_a_reason() {
    let adapter = adapter_over_tail(Ok(Vec::new()));
    let read = adapter.legacy_audit_head();
    assert_eq!(read.head, LegacyHead::empty());
    assert_eq!(
        read.unreadable, None,
        "an empty log is an answer, not an unread row"
    );
}

/// The head a store DOES hold still reads through unchanged.
#[test]
fn the_last_audit_row_is_the_head() {
    let adapter = adapter_over_tail(Ok(vec![record(41), record(42)]));
    let read = adapter.legacy_audit_head();
    assert_eq!(read.head.seq, Some(42));
    assert_eq!(read.head.hash.as_deref(), Some("hash-42"));
    assert_eq!(read.unreadable, None);
}
