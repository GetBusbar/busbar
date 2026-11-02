// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const MODEL: &str = "ordinary-unknown-model";
const FIRST_INPUT: u64 = 7;
const LATER_INPUT: u64 = 11;

struct UnknownFlushStore {
    inner: MemoryStore,
    fail_after_commit: std::sync::atomic::AtomicBool,
    unwind: bool,
}
impl RecordStore for UnknownFlushStore {
    fn supports_usage_batch_deduped(&self) -> bool {
        true
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)?;
        self.after_commit()
    }
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket, window)
    }
    fn put_usage(&self, bucket: &str, window: u64, row: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket, window, row)
    }
    fn add_usage(&self, bucket: &str, window: u64, delta: &UsageDelta) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket, window, delta)?;
        self.after_commit()
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, day: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(day)
    }
}
impl UnknownFlushStore {
    fn after_commit(&self) -> RecordStoreResult<()> {
        if self.fail_after_commit.swap(false, Ordering::SeqCst) {
            if self.unwind {
                panic!("planted unwind after ordinary usage commit");
            }
            return Err(RecordStoreError("planted lost ordinary usage reply".into()));
        }
        Ok(())
    }
}

fn accrue_plain(gov: &GovState, bucket: &str, count: u64) {
    let mut cells = gov.budget.write(bucket);
    let cell = cells
        .entry(bucket.to_string())
        .or_insert_with(|| BudgetCell::fresh(0));
    cell.accrue(MODEL, 0, &tt(count));
    cell.dirty = true;
    cell.last_touch = crate::store::now();
}

fn ordinary_unknown_result_retries_once(unwind: bool) {
    let store = Arc::new(UnknownFlushStore {
        inner: MemoryStore::new(),
        fail_after_commit: std::sync::atomic::AtomicBool::new(true),
        unwind,
    });
    let key = sample_key("vk_ordinary_unknown_commit", "ordinary-unknown-generation");
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue_plain(&gov, &key.id, FIRST_INPUT);
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_budgets()));
    assert_eq!(first.is_err(), unwind);
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT)
    );
    accrue_plain(&gov, &key.id, LATER_INPUT);
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT + LATER_INPUT),
        "a committed ordinary flush must not be applied again when its reply was unknown"
    );
}

#[test]
fn ordinary_small_usage_unknown_reply_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(false);
}

#[test]
fn ordinary_small_usage_unwind_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(true);
}
