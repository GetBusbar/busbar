// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, RecordStore as AbiStore, RecordStoreError,
    RecordStoreResult, UsageLedger, VirtualKey,
};

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
}

fn adapter_over_tail(tail: Result<Vec<AuditRecord>, String>) -> StoreAdapter {
    StoreAdapter::new(
        Arc::new(AuditTail(tail)),
        busbar_contract::abi::store::ABI_VERSION,
    )
}

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

#[test]
fn a_store_that_will_not_answer_for_its_audit_tail_names_the_reason() {
    let adapter = adapter_over_tail(Err("the backend is unreachable".to_string()));
    let read = adapter.migration_audit_head();
    assert_eq!(read.head, MigrationHead::empty(), "an unread head is empty");
    let reason = read
        .unreadable
        .expect("a store that would not answer must name the reason it did not");
    assert!(
        reason.contains("the backend is unreachable"),
        "the reason must carry what the store said, said: {reason}"
    );

    let rows = adapter.migration_ledger_rows(MigrationReadPlan::nothing());
    assert_eq!(
        rows.read_figures().unreadable.len(),
        1,
        "the unread head joins the unread cells the report already prints"
    );
}

#[test]
fn a_store_with_no_audit_rows_reads_empty_without_a_reason() {
    let adapter = adapter_over_tail(Ok(Vec::new()));
    let read = adapter.migration_audit_head();
    assert_eq!(read.head, MigrationHead::empty());
    assert_eq!(
        read.unreadable, None,
        "an empty log is an answer, not an unread row"
    );
}

#[test]
fn the_last_audit_row_is_the_head() {
    let adapter = adapter_over_tail(Ok(vec![record(41), record(42)]));
    let read = adapter.migration_audit_head();
    assert_eq!(read.head.seq, Some(42));
    assert_eq!(read.head.hash.as_deref(), Some("hash-42"));
    assert_eq!(read.unreadable, None);
}
